"""Vérification manuelle de is_didactic_context (ex-test_soupape.py)."""

from agentguard.patterns import is_didactic_context

print(
    is_didactic_context("Explain the string 'rm -rf /' for training in a blog article")
)
