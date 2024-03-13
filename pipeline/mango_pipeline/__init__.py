from pathlib import Path
PROJECT_DIR = Path(__file__).resolve(strict=True).parent.parent.parent.absolute()

from mango_pipeline.local import PipelineLocal
from mango_pipeline.remote import PipelineRemote
from mango_pipeline.kube import PipelineKube


__version__ = "0.0.1"

