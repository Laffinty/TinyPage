"""Tag graph visualization using Canvas."""

TAG_GRAPH_SCRIPT = """
<canvas id="tag-graph" width="800" height="500" style="max-width:100%;border:1px solid var(--border);border-radius:var(--radius);margin:2rem 0;"></canvas>
<script>
(function() {
  var canvas = document.getElementById('tag-graph');
  if (!canvas) return;

  var ctx = canvas.getContext('2d');
  var isDark = document.documentElement.classList.contains('dark');
  var textColor = isDark ? '#eaeaea' : '#333';
  var lineColor = isDark ? 'rgba(100,150,255,0.4)' : 'rgba(50,100,200,0.3)';
  var nodeRadius = 6;

  var tags = [];
  var connections = [];
  var tagPositions = {};

  function parseTagData() {
    var metaElements = document.querySelectorAll('.post-tags .tag');
    metaElements.forEach(function(el) {
      var tagName = el.textContent.trim();
      if (tagName && !tags.some(function(t) { return t.name === tagName; })) {
        tags.push({ name: tagName, x: 0, y: 0 });
      }
    });
  }

  function calculateConnections() {
    var articleTags = [];
    var postPreviews = document.querySelectorAll('.post-preview');
    postPreviews.forEach(function(preview) {
      var tagEls = preview.querySelectorAll('.tag');
      var tagNames = [];
      tagEls.forEach(function(el) {
        tagNames.push(el.textContent.trim());
      });
      if (tagNames.length > 0) {
        articleTags.push(tagNames);
      }
    });

    for (var i = 0; i < tags.length; i++) {
      for (var j = i + 1; j < tags.length; j++) {
        var count = 0;
        for (var k = 0; k < articleTags.length; k++) {
          if (articleTags[k].includes(tags[i].name) && articleTags[k].includes(tags[j].name)) {
            count++;
          }
        }
        if (count > 0) {
          connections.push({ source: i, target: j, weight: count });
        }
      }
    }
  }

  function positionNodes() {
    var width = canvas.width;
    var height = canvas.height;
    var centerX = width / 2;
    var centerY = height / 2;
    var radius = Math.min(width, height) * 0.35;

    for (var i = 0; i < tags.length; i++) {
      var angle = (2 * Math.PI * i) / tags.length - Math.PI / 2;
      tags[i].x = centerX + radius * Math.cos(angle);
      tags[i].y = centerY + radius * Math.sin(angle);
      tagPositions[tags[i].name] = { x: tags[i].x, y: tags[i].y };
    }
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.lineWidth = 1;
    for (var i = 0; i < connections.length; i++) {
      var c = connections[i];
      var source = tags[c.source];
      var target = tags[c.target];
      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.strokeStyle = lineColor;
      ctx.globalAlpha = Math.min(c.weight * 0.3, 0.8);
      ctx.stroke();
    }

    ctx.globalAlpha = 1;
    for (var i = 0; i < tags.length; i++) {
      var tag = tags[i];

      ctx.beginPath();
      ctx.arc(tag.x, tag.y, nodeRadius, 0, 2 * Math.PI);
      ctx.fillStyle = 'var(--accent, #e74c3c)';
      ctx.fill();

      ctx.fillStyle = textColor;
      ctx.font = '12px system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(tag.name, tag.x, tag.y - nodeRadius - 5);
    }
  }

  function resize() {
    var rect = canvas.getBoundingClientRect();
    canvas.width = Math.min(800, rect.width);
    canvas.height = Math.min(500, rect.width * 0.625);
    positionNodes();
    draw();
  }

  parseTagData();
  if (tags.length > 1) {
    calculateConnections();
    resize();
    window.addEventListener('resize', resize);
  } else {
    canvas.style.display = 'none';
  }
})();
</script>
"""


def get_tag_graph_html() -> str:
    """Return the tag graph HTML and script."""
    return TAG_GRAPH_SCRIPT


def get_tag_graph_container_html() -> str:
    """Return just the container HTML for the tag graph."""
    return '<div class="tag-graph-container"></div>'
