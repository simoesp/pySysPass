"""Render a secret as a PNG, as sysPass PHP ``ImageUtil::convertText()`` does.

PHP shows passwords as images when ``account_pass_to_image`` is on, when the
user's fixed ``account.password`` preset sets ``useImage``, and for public
links when ``publinks_image_enabled`` is on. It is a display control against
shoulder surfing and page scraping, not an access control: anyone allowed to
copy the password still receives the text.
"""
import base64
import io
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

# ImageUtil::convertText(): 30 px high, strlen * 10 wide, grey on light grey,
# 10 pt text (about 13 px in GD) with its baseline at (10, 20).
_HEIGHT = 30
_BACKGROUND = (245, 245, 245)
_FOREGROUND = (128, 128, 128)
_FONT_PX = 13


@lru_cache(maxsize=1)
def _font():
    return ImageFont.load_default(size=_FONT_PX)


def text_to_png_base64(text: str) -> str:
    """Base64 PNG of ``text``; wide enough to never clip it (PHP may)."""
    font = _font()
    width = max(len(text.encode("utf-8")) * 10, int(font.getlength(text)) + 20, 20)
    image = Image.new("RGB", (width, _HEIGHT), _BACKGROUND)
    ImageDraw.Draw(image).text((10, 20), text, fill=_FOREGROUND, font=font, anchor="ls")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")
