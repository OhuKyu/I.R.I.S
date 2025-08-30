from flask import Flask, render_template, request, jsonify
from iris import IRIS
from cache_manager import CacheManager
import json
import os

app = Flask(__name__)

try:
    iris = IRIS()
    cache = CacheManager()
    cache.init_database()
    print("✅ I.R.I.S and cache system initialized successfully")
except Exception as e:
    print(f"❌ Error initializing components: {e}")
    iris = None
    cache = None

@app.route('/health')
def health_check():
    """Health check endpoint for Railway"""
    if iris is None or cache is None:
        return jsonify({'status': 'unhealthy', 'message': 'Components not initialized'}), 503
    
    try:
        # Test cache connection
        cache.get_stats()
        return jsonify({
            'status': 'healthy',
            'message': 'I.R.I.S is running',
            'components': {
                'iris': 'ok',
                'cache': 'ok'
            }
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'message': str(e)}), 503

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/cache/stats', methods=['GET'])
def cache_stats():
    """Get cache statistics"""
    try:
        stats = cache.get_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Clear all cache"""
    try:
        cache.clear_all()
        return jsonify({'message': 'Cache cleared successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cache/clear-expired', methods=['POST'])
def clear_expired_cache():
    """Clear expired cache entries"""
    try:
        cache.clear_expired()
        return jsonify({'message': 'Expired cache cleared successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/explain', methods=['POST'])
def api_explain():
    if iris is None:
        return jsonify({'error': 'I.R.I.S not initialized'}), 503
        
    try:
        data = request.get_json()
        question = data.get('question', '')
        if not question:
            return jsonify({'error': 'Question is required'}), 400
        
        result = iris.explain(question)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/summarize', methods=['POST'])
def api_summarize():
    try:
        data = request.get_json()
        text = data.get('text', '')
        ratio = data.get('ratio', 0.4)
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        result = iris.summarize(text, ratio)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/explain_code', methods=['POST'])
def api_explain_code():
    try:
        data = request.get_json()
        code = data.get('code', '')
        language = data.get('language', 'python')
        
        if not code:
            return jsonify({'error': 'Code is required'}), 400
        
        result = iris.explain_code(code, language)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/flashcards', methods=['POST'])
def api_flashcards():
    try:
        data = request.get_json()
        text = data.get('text', '')
        n = data.get('n', 5)
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        flashcards = iris.make_flashcards(text, n)
        result = [{'front': card.front, 'back': card.back} for card in flashcards]
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/quiz', methods=['POST'])
def api_quiz():
    try:
        data = request.get_json()
        text = data.get('text', '')
        n = data.get('n', 3)
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        quiz_items = iris.quiz(text, n)
        result = [{
            'question': item.question,
            'options': item.options,
            'answer': item.answer,
            'explanation': item.explanation
        } for item in quiz_items]
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/study_plan', methods=['POST'])
def api_study_plan():
    try:
        data = request.get_json()
        goal = data.get('goal', '')
        days = data.get('days', 7)
        hours = data.get('hours', 2)
        
        if not goal:
            return jsonify({'error': 'Goal is required'}), 400
        
        result = iris.study_plan(goal, days, hours)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting I.R.I.S for Railway deployment...")
    
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('RAILWAY_ENVIRONMENT') != 'production'
    
    print(f"🌐 Server starting on port {port}")
    print(f"🔧 Debug mode: {debug}")
    
    app.run(debug=debug, host='0.0.0.0', port=port)
