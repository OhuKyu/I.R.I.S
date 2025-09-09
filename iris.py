import os, sys, json, textwrap
from dataclasses import dataclass
from typing import List

from openai import OpenAI
import google.generativeai as genai
from dotenv import load_dotenv
from cache_manager import CacheManager

# Load API keys
load_dotenv()
MONICA_KEY = os.getenv("MONICA_API_KEY")
GEMINI_KEY = os.getenv("GEMINI_API_KEY")

if not MONICA_KEY or not GEMINI_KEY:
    # Thay vì sys.exit(1) để process không chết trên platform như Railway.
    print("⚠️ Missing API keys: MONICA_API_KEY or GEMINI_API_KEY not set. Set environment variables to enable AI calls.")
    MONICA_KEY = MONICA_KEY or ""
    GEMINI_KEY = GEMINI_KEY or ""

# Monica client (OpenAI compatible)
monica = OpenAI(base_url="https://openapi.monica.im/v1", api_key=MONICA_KEY)

# Gemini client
genai.configure(api_key=GEMINI_KEY)
gemini = genai.GenerativeModel("gemini-2.0-flash")

SYSTEM_GUIDELINES = """
Bạn là I.R.I.S — Intelligent Reliable Interactive Study Assistant.
Nguyên tắc:
- Trả lời súc tích trước, mở rộng khi cần.
- Công thức/ký hiệu nên đặt trong \`\`\`...\`\`\`.
- Khi sinh quiz/flashcards: kèm đáp án, giải thích ngắn gọn.
- Khi không chắc: nêu giả định/hướng tự kiểm tra.
"""

cache = CacheManager()

# ====== Model Fallback Chain ======
def call_ai(prompt: str, temperature=0.6, function_type="general") -> str:
    # Generate cache key
    cache_key = cache.generate_cache_key(function_type, prompt=prompt, temperature=temperature)
    
    # Try to get from cache
    cached_result = cache.get_cache(cache_key)
    if cached_result:
        print(f"🎯 Cache HIT for {function_type}")
        return cached_result
    
    print(f"🔄 Cache MISS for {function_type} - calling AI...")
    
    models = ["gpt-4o-mini", "deepseek-chat"]
    for m in models:
        try:
            resp = monica.chat.completions.create(
                model=m,
                messages=[
                    {"role": "system", "content": SYSTEM_GUIDELINES},
                    {"role": "user", "content": prompt},
                ],
                temperature=temperature,
            )
            result = resp.choices[0].message.content.strip()
            cache.set_cache(cache_key, function_type, {"prompt": prompt, "temperature": temperature}, result)
            return result
        except Exception as e:
            print(f"⚠️ {m} failed: {e}")
            continue

    # Fallback cuối cùng → Gemini
    try:
        resp = gemini.generate_content([SYSTEM_GUIDELINES, prompt])
        result = resp.text.strip()
        cache.set_cache(cache_key, function_type, {"prompt": prompt, "temperature": temperature}, result)
        return result
    except Exception as e:
        print(f"⚠️ Gemini failed: {e}")
        return "❌ All models failed. Please check your API keys or network connection."

def call_ai_stream(prompt: str, temperature=0.6, function_type: str = "general"):
    """Yield small text chunks from provider if streaming is supported; otherwise yield full text once."""
    # Try Monica (OpenAI compatible) with stream
    try:
        stream = monica.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_GUIDELINES},
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
            stream=True,
        )
        full_text = []
        for chunk in stream:
            try:
                delta = chunk.choices[0].delta.get("content") or ""
            except Exception:
                delta = ""
            if delta:
                full_text.append(delta)
                yield delta
        # Save to cache when done
        final = "".join(full_text).strip()
        if final:
            cache_key = cache.generate_cache_key(function_type, prompt=prompt, temperature=temperature)
            cache.set_cache(cache_key, function_type, {"prompt": prompt, "temperature": temperature}, final)
        return
    except Exception as e:
        print(f"⚠️ stream fallback: {e}")
    # Fallback: non-stream call, yield once
    text = call_ai(prompt, temperature=temperature, function_type=function_type)
    yield text

# ====== Data Structures ======
@dataclass
class Flashcard:
    front: str
    back: str


@dataclass
class QuizItem:
    question: str
    options: List[str]
    answer: str
    explanation: str


# ====== IRIS Class ======
class IRIS:
    def __init__(self):
        pass

    def chat(self, message: str) -> str:
        """General-purpose conversational reply, free-form.
        Keeps the educational tone but allows any topic from motivation to guidance.
        """
        prompt = message.strip()
        return call_ai(prompt, function_type="chat")

    def chat_stream(self, message: str):
        prompt = message.strip()
        for chunk in call_ai_stream(prompt, function_type="chat"):
            yield chunk

    def explain(self, question: str) -> str:
        prompt = f"Giải thích khái niệm hoặc câu hỏi học tập sau một cách chi tiết nhưng súc tích:\n{question}"
        return call_ai(prompt, function_type="explain")

    def summarize(self, text: str, ratio: float = 0.4) -> str:
        prompt = f"Tóm tắt văn bản sau còn khoảng {int(ratio*100)}% độ dài gốc, giữ nguyên ý chính:\n{text}"
        return call_ai(prompt, function_type="summarize")

    def explain_code(self, code: str, language: str = "python") -> str:
        prompt = f"Giải thích mã code sau một cách chi tiết, bao gồm chức năng từng phần và cách hoạt động. Ngôn ngữ: {language}\n\`\`\`{'python' if language.lower() == 'python' else language}\n{code}\n\`\`\`"
        return call_ai(prompt, function_type="explain_code")

    def make_flashcards(self, text: str, n: int = 5) -> List[Flashcard]:
        prompt = f"""
        Tạo {n} flashcard ở định dạng JSON THUẦN (chỉ JSON, không giải thích, không dùng ```),
        mỗi phần tử có các khóa: "front" và "back" (và tùy chọn "explanation").
        Nếu model sinh ra "question/answer" thì hãy đổi tên thành "front/back".
        Nội dung: {text}
        Ví dụ: [{{"front":"Hỏi?","back":"Đáp","explanation":"…"}}]
        """
        raw = call_ai(prompt, function_type="flashcards")
        try:
            data = json.loads(self._extract_json(raw))
            if isinstance(data, dict) and 'flashcards' in data:
                data = data['flashcards']
            normalized = []
            for item in data:
                if isinstance(item, dict):
                    front = item.get('front') or item.get('question') or item.get('q') or 'N/A'
                    back = item.get('back') or item.get('answer') or item.get('a') or 'N/A'
                    explanation = item.get('explanation') or item.get('note') or ''
                    normalized.append(Flashcard(front=front, back=back if explanation == '' else f"{back}\n\n{explanation}"))
            if not normalized:
                raise ValueError('Empty flashcards after normalization')
            return normalized[:n]
        except Exception:
            return [Flashcard(front="N/A", back=raw)]

    def quiz(self, text: str, n: int = 3) -> List[QuizItem]:
        prompt = f"""
        Tạo {n} câu hỏi trắc nghiệm, trả về JSON THUẦN (chỉ JSON, không dùng ```),
        mỗi phần tử có: "question" (string), "options" (array 3-5 lựa chọn), "answer" (string đúng), "explanation" (string ngắn).
        Nội dung: {text}
        Ví dụ: [{{"question":"…","options":["A","B"],"answer":"A","explanation":"…"}}]
        """
        raw = call_ai(prompt, function_type="quiz")
        try:
            data = json.loads(self._extract_json(raw))
            if isinstance(data, dict) and 'quiz' in data:
                data = data['quiz']
            normalized: List[QuizItem] = []
            for item in data:
                if isinstance(item, dict):
                    question = item.get('question') or item.get('q') or 'N/A'
                    options = item.get('options') or item.get('choices') or []
                    answer = item.get('answer') or item.get('correct') or 'N/A'
                    explanation = item.get('explanation') or item.get('why') or ''
                    if not isinstance(options, list):
                        options = []
                    normalized.append(QuizItem(question=question, options=options, answer=answer, explanation=explanation))
            if not normalized:
                raise ValueError('Empty quiz after normalization')
            return normalized[:n]
        except Exception:
            return [QuizItem(question="N/A", options=[], answer="N/A", explanation=raw)]

    def study_plan(self, goal: str, days: int = 7, hours: int = 2) -> str:
        prompt = f"""
        Mục tiêu: {goal}
        Lập kế hoạch học trong {days} ngày, mỗi ngày {hours} giờ.
        """
        return call_ai(prompt, function_type="study_plan")

    def _extract_json(self, text: str) -> str:
        """Extract JSON payload from LLM text.
        Supports blocks like ```json ... ```, ``json ... ``, or inline JSON mixed with prose.
        """
        import re

        if not text:
            return text

        s = text.strip()

        # 1) Try to find content inside code fences with 2-3 backticks
        fence_pattern = re.compile(r"`{2,3}[a-zA-Z]*\s*([\s\S]*?)`{2,3}")
        for match in fence_pattern.finditer(s):
            blk = match.group(1).strip()
            if blk.startswith('{') or blk.startswith('['):
                return blk

        # 2) Fallback: find first JSON-like substring { ... } or [ ... ]
        #    Try progressively larger spans until json.loads succeeds upstream
        bracket_pattern = re.compile(r"(\{[\s\S]*\}|\[[\s\S]*\])")
        candidates = bracket_pattern.findall(s)
        for cand in candidates:
            cand_strip = cand.strip()
            if cand_strip.startswith('{') or cand_strip.startswith('['):
                return cand_strip

        # 3) As last resort, return original trimmed text
        return s