# The image the benchmark figures are drawn in: matplotlib and IBM Plex Sans (converted from the
# official web fonts, which matplotlib cannot read directly).
#   docker build -t skill-scanner-figures -f scripts/benchmark-figures.Dockerfile scripts
FROM python:3.12-slim
RUN pip install --no-cache-dir matplotlib==3.9.2 fonttools==4.54.1 brotli==1.1.0 \
  && mkdir -p /usr/share/fonts/plex && cd /usr/share/fonts/plex \
  && for w in Light Regular Medium SemiBold Bold; do \
       python -c "import urllib.request as u; u.urlretrieve('https://cdn.jsdelivr.net/npm/@ibm/plex-sans@1.1.0/fonts/complete/woff2/IBMPlexSans-$w.woff2', 'IBMPlexSans-$w.woff2')" \
       && python -m fontTools.ttLib.woff2 decompress IBMPlexSans-$w.woff2 && rm IBMPlexSans-$w.woff2; \
     done \
  && python -c "import matplotlib.font_manager as f; f._load_fontmanager(try_read_cache=False)"
