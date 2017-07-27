Intoduction to *dizzy*
======================

Structure of *.dizz* files
--------------------------

A single packet is described by a so called *.dizz* file. Some example files can be found in the [dizzfiles](https://github.com/ernw/dizzfiles) repository. These files are Python code, so they have to be written in proper Python syntax. They consist of three variables which need to be defined. The first variable is the **name** of
the packet:

```python
name = "test"
```

The second variable is called **objects** and describes the packet fields. It's a Python list with all the fields listed:

```python
objects = [
    ...
]
```

Inside of that list you can use some pre-defined functions which generate the actual data during parsing. the functions are called *field()*, *list()*, *rand()* and *link()*. they take different arguments, as listed below:

  * The *field()* function takes 4 arguments, which are: the **name** of the field [a string], the **length** of the field (in bits!) [an int] OR *None* for a field with variable length, the default **value** for that field [a string] and the fuzzing **mode** for that field [can be *none* for not fuzzing that field at all, *std* for fuzzing some values on the upper and lower value border, and *full* for fuzzing all possible values].

    ```python
    objects = [
        field("len", 8, "\x00", none),
        ...
    ]
    ```

  * The *list()* function takes 3 arguments: the **name** of the field [a string], the default **value** of the field [a string] and the **path** to a file, containing possible values for that field (one value per line, all values will be inserted while fuzzing).

    ```python
    objects = [
        field("len", 8, "\x00", none),
        list("test4", "happens?", "lib/test.txt"),
        ...
    ]
    ```

  * The *rand()* function takes 2 arguments: the **name** of the field [a string] and the **length** of the field (in bits!) [an int]. The value of that field will be a new random on, each time a packet is generated.

    ```python
    objects = [
        field("len", 8, "\x00", none),
        list("test4", "happens?", "lib/test.txt"),
        rand("random", 12),
        ...
    ]
    ```

  * The *link()* function takes 2 arguments: the **name** of the field [a string] and the **name** of an other (previous defined) field. The value of that field will always be the same as the source field, also the length will always be the same.

    ```python
    objects = [
        field("len", 8, "\x00", none),
        list("test4", "happens?", "lib/test.txt"),
        rand("random", 12),
        link("same_random", "random"),
        ...
    ]
    ```
    
The third variable is called **functions** and it is also a Python list. It represents a set of functions that are called against the generated raw packet, before it is sent out. Currently the functions *length()*, *lambda\_legth()*, *csum()*, *lambda\_csum()* and *lambda2_csum()* are available.

  * The *length()* function takes 3 argument: the name of the **destination** field, where the value should be updated with the calculated length [a string], the name of the **first** field, that should be in the length calculation (the starting point) [a string] and the name of the **last** field, that should be in the length calculation (the end point).

    ```python
    functions = [
        length("len", "test4", "same_random"),
        ...
    ]
    ```

  * The *lambda\_length()* function takes 4 arguments: the name of the **destination** field, where the value should be updated with the calculated length [a string], the name of the **first** field, that should be in the length calculation (the starting point) [a string], the name of the **last** field, that should be in the length calculation (the end point) and a function, which will be called after the length is calculated, with the length as an argument [int].

    ```python
    functions = [
        length("len", "align-mod", "value"),
        lambda_length("len2", "align-nomod", "align-mod", lambda x: x + 2),
        ...
    ]
    ```

  * The *csum()* function takes 4 arguments: the name of the **destination** field, which value should be updated with the calculated checksum [a string], the name of the **first** field, that should be the input of the checksum calculation (the starting point) [a string], the name of the **last** field, that should be the input of the checksum calculation (the end point) [a string] and the name of the **checksum** [a string], were currently only 'inet' (rfc1071) is implemented.

    ```python
    functions = [  
        length("len", "align-mod", "value"),
        lambda_length("len2", "align-nomod", "align-mod", lambda x: x + 2),
        csum("csum", "align-mod", "value", "inet"),
        ...
    ]
    ```

*Note*: There are some weird looking *.dizz* files, which are auto-generated from an old dizzy version. They are working and will be replaced by more readable ones in the future.


Structure of *.act* files
-------------------------

Once you want to get stateful, you need to write interaction in *.act* files. These file are Python code as well. they also got 3 variables, **name** for the name of the interaction [a string], **objects** which is a Python list of dizzes (you can use a pre-defined function here as well) and **functions**, which also is a Python list.

  * The *dizz()* function takes 2 arguments: the **name** of the paket [a string] and the **path** of the *.dizz* file [a string]. These are the single packets of the interaction.

    ```python
    objects = [
        dizz("test_dizz", "dizzes/test.dizz"),
        dizz("2nd step", "dizzes/example.dizz"),
        ...
    ]
    ```

There is a **functions** variable as well, which contains either *copy()* or *adv\_copy()* functions:

  * The *copy()* function takes 4 arguments: the **step** in which the function should be executed (1=on recv after the first packet [.dizz file], 2=on recv after the second, ...) [an int], the name of the **destination** field in the second dizz [a string] and two offsets, the **start** and the **end** point of the data that should be copied [ints]. These offsets are byte offsets inside of the received data (depending on the used session the received data starts at the ethernet dst [L2] or the tcp/udp/sctp payload [L4]).

    ```python
    functions = [
        copy(1, "TEID", 4, 8),
        ...
    ]
    ```

  * The *adv\_copy()* function takes 2 arguments: the **step** in which the function should be executed [int] and a function **reference**. The function given will be called with the received data and the dizz of the next step (this should not be used without deep knowledge of the dizzy code ;)
