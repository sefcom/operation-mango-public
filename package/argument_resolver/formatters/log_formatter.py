import datetime
import logging

from pathlib import Path

from rich.logging import RichHandler
from rich.highlighter import NullHighlighter
from rich.console import Console
from rich.progress import TextColumn
from rich.text import Text


class CustomFormatter(logging.Formatter):

    grey = "[white]"
    green = "[green]"
    blue = "[blue]"
    bold_blue = "[bold blue]"
    light_blue = "[#00ffff]"
    yellow = "[yellow]"
    red = "[red]"
    bold_red = "[bold red]"
    reset = "[/]"
    # format = "%(levelname)s | %(asctime)s | %(name)s | %(message)s"

    FORMATS = {
        logging.DEBUG: green,
        logging.INFO: grey,
        logging.WARNING: yellow,
        logging.ERROR: red,
        logging.CRITICAL: bold_red,
    }

    def format(self, record):
        log_color = self.FORMATS.get(record.levelno)
        level = record.levelname + " "
        log_str = level.ljust(10)
        log_str += f"| {datetime.datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')},"
        log_str += str(record.lineno).ljust(3, " ")
        log_str += f" |{log_color} "
        log_str += record.name
        log_str += f" {self.reset}|{log_color} "
        log_str += record.getMessage()
        log_str += self.reset
        return log_str


class CustomColorRichHandler(RichHandler):
    def render_message(self, record, message: str) -> "ConsoleRenderable":
        msg = super().render_message(record, message)
        color = (
            CustomFormatter.FORMATS.get(record.levelno)
            .replace("[", "")
            .replace("]", "")
        )
        msg.style = color
        return msg


class CustomPathRichHandler(CustomColorRichHandler):
    def emit(self, record):
        record.pathname = ""
        super().emit(record)


def make_logger(log_level=logging.INFO, should_debug=False):
    log = logging.getLogger("FastFRUIT")
    log.setLevel(logging.DEBUG)
    if log.handlers:
        return log

    log.propagate = False
    debug_file = Path("/tmp/mango.out")

    if should_debug:
        if debug_file.exists():
            debug_file.unlink()
        console = Console(file=debug_file.open("a+"), force_terminal=True)
        log.addHandler(
            CustomPathRichHandler(
                level=log_level,
                console=console,
                highlighter=NullHighlighter(),
                markup=True,
                rich_tracebacks=True,
                keywords=[],
            )
        )
    log.addHandler(
        CustomPathRichHandler(
            level=log_level,
            highlighter=NullHighlighter(),
            markup=True,
            keywords=[],
            rich_tracebacks=True,
        )
    )

    return log


class CustomTextColumn(TextColumn):
    """A column containing text."""

    def render(self, task: "Task") -> Text:
        if task.total is None:
            if task.completed == 0:
                _text = ""
            else:
                _text = f"{task.completed}"
        else:
            _text = self.text_format.format(task=task)
        if self.markup:
            text = Text.from_markup(_text, style=self.style, justify=self.justify)
        else:
            text = Text(_text, style=self.style, justify=self.justify)
        if self.highlighter:
            self.highlighter.highlight(text)
        return text
