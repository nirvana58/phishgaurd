# sandbox/Dockerfile
#
# Isolated headless-browser image used to "detonate" suspicious URLs --
# visit them for real, screenshot them, and observe behavior -- without
# any of that ever touching the host machine directly.
#
# This container is intentionally run with NO host filesystem access
# beyond a single output-only mount (see core/url_sandbox.py for the
# `docker run` flags: --read-only, --cap-drop=ALL, --security-opt
# no-new-privileges, non-root user, memory/CPU limits). The isolation
# lives in how the container is RUN, not just in this image -- an image
# alone is not a sandbox.
#
# NOTE ON BUILD SIZE: this uses a slim Python base + installs ONLY
# Chromium (via `playwright install --with-deps chromium`), rather than
# the full mcr.microsoft.com/playwright/python image, which bundles
# Chromium + Firefox + WebKit (and all three browsers' system deps)
# whether you use them or not. detonate.py only launches Chromium, so
# the other two engines were pure download weight. This roughly halves
# the image size and first-build time.

FROM python:3.12-slim-bookworm

WORKDIR /app

# NOTE ON DEPS: previously hand-listed every system library via apt-get,
# but that list broke as soon as the python:3.12-slim base image moved to
# a newer Debian release (trixie) that renamed some packages
# (libgdk-pixbuf2.0-0, libpango-gobject-0). Switched to `playwright
# install --with-deps` to let Playwright resolve its own OS deps instead
# of hand-listing them — but Playwright 1.48.0's dependency installer
# doesn't have trixie support yet either (it fails looking for
# ttf-unifont / ttf-ubuntu-font-family, which don't exist under those
# names in trixie's repos). Fixed by pinning the base image to
# `python:3.12-slim-bookworm` explicitly above, rather than floating on
# whatever Debian release the generic `slim` tag currently maps to.
# Revisit the bookworm pin once Playwright ships trixie support and/or
# you bump the playwright version below.

RUN pip install --no-cache-dir playwright==1.48.0 \
    && playwright install --with-deps chromium

RUN useradd --create-home --uid 1000 sandboxuser \
    && mkdir -p /output \
    && chown -R sandboxuser:sandboxuser /app /output

COPY detonate.py /app/detonate.py

USER sandboxuser

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "/app/detonate.py"]