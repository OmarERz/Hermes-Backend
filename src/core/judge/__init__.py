"""LLM judge (docs/07): mode 1 scoring reviews over review packages, validated by code (D-022).

The judge only proposes reasons through strict tools; code validates every call, sums the accepted reasons and
hands the adjustment to the scoring engine. It never writes the final score, iTop or Slack (L8).
"""
