"""No network calls: ensure provider credentials and endpoints stay isolated."""
import sys
from types import ModuleType
from agentshield.evaluation.launch import build_defender


def test_groq_defender_uses_groq_endpoint_and_key(monkeypatch):
    calls = []
    fake = ModuleType('langchain_openai')
    fake.ChatOpenAI = lambda **kwargs: calls.append(kwargs) or kwargs
    monkeypatch.setitem(sys.modules, 'langchain_openai', fake)
    monkeypatch.setenv('OPENAI_API_KEY', 'openai-test-key')
    monkeypatch.setenv('GROQ_API_KEY', 'groq-test-key')
    monkeypatch.delenv('GROQ_BASE_URL', raising=False)
    build_defender('llama-3.1-8b-instant', 'groq')
    assert calls[0]['model'] == 'llama-3.1-8b-instant'
    assert calls[0]['api_key'] == 'groq-test-key'
    assert calls[0]['base_url'] == 'https://api.groq.com/openai/v1'
    assert calls[0]['api_key'] != 'openai-test-key'


def test_openai_defender_does_not_inherit_groq_endpoint(monkeypatch):
    calls = []
    fake = ModuleType('langchain_openai')
    fake.ChatOpenAI = lambda **kwargs: calls.append(kwargs) or kwargs
    monkeypatch.setitem(sys.modules, 'langchain_openai', fake)
    monkeypatch.setenv('GROQ_API_KEY', 'groq-test-key')
    build_defender('gpt-6-luna', 'openai')
    assert calls[0]['model'] == 'gpt-6-luna'
    assert 'base_url' not in calls[0]
    assert 'api_key' not in calls[0]
