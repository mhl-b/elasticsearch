% This is generated by ESQL's AbstractFunctionTestCase. Do not edit it. See ../README.md for how to regenerate it.

### COUNT
Returns the total number (count) of input values.

```esql
FROM employees
| STATS COUNT(height)
```
