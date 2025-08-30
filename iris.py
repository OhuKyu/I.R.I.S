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
        Tạo {n} flashcard JSON từ nội dung sau:
        Văn bản: {text}
        """
        raw = call_ai(prompt, function_type="flashcards")
        try:
            data = json.loads(self._extract_json(raw))
            return [Flashcard(**d) for d in data][:n]
        except Exception:
            return [Flashcard(front="N/A", back=raw)]

    def quiz(self, text: str, n: int = 3) -> List[QuizItem]:
        prompt = f"""
        Tạo {n} câu trắc nghiệm (JSON) từ nội dung sau:
        Văn bản: {text}
        """
        raw = call_ai(prompt, function_type="quiz")
        try:
            data = json.loads(self._extract_json(raw))
            return [QuizItem(**d) for d in data][:n]
        except Exception:
            return [QuizItem(question="N/A", options=[], answer="N/A", explanation=raw)]

    def study_plan(self, goal: str, days: int = 7, hours: int = 2) -> str:
        prompt = f"""
        Mục tiêu: {goal}
        Lập kế hoạch học trong {days} ngày, mỗi ngày {hours} giờ.
        """
        return call_ai(prompt, function_type="study_plan")

    def _extract_json(self, text: str) -> str:
        if "\`\`\`" in text:
            parts = text.split("\`\`\`")
            for blk in parts:
                if blk.strip().startswith("{") or blk.strip().startswith("["):
                    return blk.strip()
        return text.strip()