# RDA
### Assumed Execution
We assume that only functions which touch arguments that flow to our sink, either in parameters or in return values, are relevant.
All other functions are skipped during analysis. 

#### Cons:
- Pointer Aliasing is excluded from this assumption

#### Finding Callees for Assumed Execution
Find the transitive closure of the sink node in the dep graph. 
Take all root nodes and DFS them in the graph.
Analyze only the calles that have parameters included in the resulting nodes.

If the final sink has a TOP value for the pointer then we ignore that index

# Engine Vex
### Guarded Load
Guarded loads can contain conditions that will always result in a true result.
Thus, we assume that if a guarded load occurs and one of the values is a top, collapse into the other value if it is resolvable.