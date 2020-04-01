# Python Coding Style

In order to make the code more maintainable, and helps developers understand code in reviews, we have a set of style guidelines for clarity.

* Please read [pep8 style guide](https://www.python.org/dev/peps/pep-0008/) before you try to contribute any code. The guidelines gives some basic coding conventions, including:
    - Code lay-out
    - String Quotes
    - Naming Conventions
    - Comments

* Some general guidelines you should follow like following when you write SDK code:
    - Use only UNIX style newlines (\n), not Windows style (\r\n)
    - It is preferred to wrap long lines in parentheses and not a backslash for line continuation.
    - Do not import more than one module per line
    - Docstrings should not start with a space.
    - Multi line docstrings should end on a new line.
    - Multi line docstrings should start without a leading new line.
    - Multi line docstrings should start with a one line summary followed by an empty line.

* For every api which will be used by our client, the api Docstrings are mandatory. We are here following the Python docstring format. For example:

```
def square_root(n):
    """Calculate the square root of a number

    Args:
        n (int): the number to get the square root of
    
    Returns:
        square_root (float): the square root of n
    
    Raises:
        TypeError: if n is not a number
        ValueError: if n is negative
    """
    pass
```

## License <a name="license"></a>

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This document is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
