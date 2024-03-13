## Adding New Handlers
Create an x.py file in the following format:
```python
import logging

from .base import HandlerBase

LOGGER = logging.getLogger("handlers.yourclass.h")

class YourClass(HandlerBase):
    
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_funcname(
        self,
        state: "ReachingDefinitionsState",
        codeloc: "CodeLocation",
    ):
        """
        :param LiveDefinitions state::       Register and memory definitions and uses
        :param Codeloc codeloc:              Code location of the call
        """
        ...
        ...
        ...
        return True, state

```
Each handler should be created as function following `handle_funcname` i.e. `handle_strcmp`
Each handler function should return `True` if analyzed and the `state`