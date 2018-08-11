# faultreiber
`faultreiber` generates a parser library in C for a structured file format. The input is an XML file that describes the format.<br/>
The C source code will be in the form of multiple source and header files. a makefile is also included.<br/>
The generated source code does not include a main.<br/>

## faultreiber XML file
The root node should have two childs, named exactly `READ` and `DEFINITION`(order not important).<br/>
The `READ` node will include the actual structures that the parser will read and can return.<br/>
The `DEFINITION` node includes the definitions for the structures that are aggregate.<br/>

## Demo
For a practical example, look at the example XML file under `resources`. The XML file describes the format of a WASM object file:<br/>
To run the demo, run `run.sh`, go to the `test` direcotory and run `make`. Then run the executable.<br/>

### Rules:

Any child node of either `DEFINITION` or `READ` will have to at least have the attributes `name` and `type` defined. The presence of the attribute `count` is optional but if it's not present faultreiber will assume that the count is one.<br/>
The presence of the attribute `isaggregate` signifies the fact that the data structure is composed of other smaller parts. faultreiber will only read the children of a node that is the child of either the `DEFINITION` or `READ` node(unless a child node has the attribute `conditional` set). If a data structure requires more children then you should add a new node under `DEFINITION` and reference that node from it's parent. In other words, an aggregate node can't itself have child nodes that are aggregate.<br/>

`count`, `size`, `type` and `condition` attributes can reference a child node of the `DEFINITION` node. To do that, you should use `self::TAG`.<br/>
the tag names of the nodes that are on the same level should be unique. The `name` attribute of the nodes on the same level need to be unique as well.<br/>
The order of the nodes that appear as children of the `DEFINITION` node, even when the child nodes are referencing each other, is unimportant to faultreiber.<br/>

Tags should follow the naming convention for naming XML nodes. The `name` attributes should follow the C identifier naming convention(if the value of the `name` attribute is invalid in C as as identifier you're going to end up with code that won't even build).<br/>
The following values are valid values for the `type` attribute:<br/>
* int8
* uint8
* int16
* uint16
* int32
* uint32
* int64
* uint64
* int128
* uint128
* float
* double
* string
* FT::conditional
* self::TAG

For string nodes, the node  should either have a non-empty `size` attribute or have a `delimiter` attribute. In case a `delimiter` attribute is selected the value of the delimiter should be provided as the value of the `delimiter` attribute to the node.<br/>
Strings read through a `delimiter` node will have their delimiter attached to the end of the string(null-terminated or otherwise). String reads that have a `size` attribute will be forcefully null-terminated even if the original string was not null-terminated.<br/>

Child nodes of `READ` node that have the `unordered` attribute set, will be regarded as such, meaning they can appear in the file sporaically. Such nodes will have to have a child node with attriute `sign`.The value of the sign attribute is used to check for the presence of the parent node in the file.<br/>
`unorderedbegin` and `unorderedend` attributes denote the begenning and end of an unordered section in the `READ` node. For every unordered section, only one node needs to define the begin and end attributes. All the other nodes, including the nodes that define the `unorderedbegin` and `unorderedend` attributes, shall have the `unordered` attribute defined.<br/>
Any child of the `READ` node that is not inside an unordered block or doesnt have the `unordered` attribute set, will be regarded as ordered.<br/>

Whether `int128` or `uint128` are defined depends on your the C implementation you are using on your host. If 128-bit integers are not supported or you need to read in bigger integers, you can simply use a smaller int type and increase the `count` attribute accordingly.<br/>
The `FT::conditional` tag for a type means that the actual content of the node will depend on a value. The attribute `condition` will provide what that condition is. The value for the condition should be provided as text for the different nodes that define what the actual contents should be.<br/>
`size` attribute is currently only meaningful when the `type` attribute is set as `string` in which case it denotes the size of the string.<br/>

## Options

```bash
  -h, --help            show this help message and exit
  --targetname TARGETNAME
                        main target name
  --outdir OUTDIR       path to output dir
  --structs STRUCTS     the structs json file
  --structsinclude STRUCTSINCLUDE
                        the path to the header that's going to be included by
                        structs.h before structure declarations.
  --xml XML             paht to the xml file
  --dbg                 debug
  --datetime            print date and time in autogen files
  --inline              inlines reader funcs
  --static              statics reader funcs
  --verbose             verbose
  --forcenullterm       terminate all strings with null even if they are not
                        originally null-terminated
  --strbuffersize STRBUFFERSIZE
                        the size of the buffer for string reads
  --strbuffgrowfactor STRBUFFGROWFACTOR
                        the factor by which the strbuffer will grow
  --voidbuffersize VOIDBUFFERSIZE
                        the size of the buffer for void* buffer
  --voidbuffgrowfactor VOIDBUFFGROWFACTOR
                        the factor by which the voidbuffer will grow
  --singlefile          the generated code will be put in a single file
  --singlefilename SINGLEFILENAME
                        name of the single file
```


## limitations
Big-Endian reads are not supported.<br/>
None-byte-sized raw reads are not supported.<br/>

## makefile
To get a list of the targets the makfile supports you can run its `help` target.<br/>

## TODO
All the items under limitations.<br/>
Figure out what the license of the generated code is.<br/>

## Projects
The list of the projects that use faulreiber:<br/>
* [bruiser](https://github.com/bloodstalker/mutator/tree/master/bruiser)<br/>

## License
`faultreiber` along with the makefile, are provided under MIT. I'm not sure whether the generated code is considered "derived work", but if it is, then the generated code will also fall under MIT<br/>
