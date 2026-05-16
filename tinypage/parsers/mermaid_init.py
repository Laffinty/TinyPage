"""Mermaid diagram initialization for frontend rendering."""

MERMAID_CDN = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"

MERMAID_INIT_SCRIPT = f"""
<script src="{MERMAID_CDN}"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {{
  if (typeof mermaid !== 'undefined') {{
    mermaid.initialize {{
      startOnLoad: true,
      theme: document.documentElement.classList.contains('dark') ? 'dark' : 'default',
      securityLevel: 'loose',
    }};
    mermaid.run({{
      querySelector: '.language-mermaid, .mermaid',
    }});
  }}
}});
</script>
"""


def get_mermaid_script() -> str:
    """Return the Mermaid initialization script HTML."""
    return MERMAID_INIT_SCRIPT
