# faultreiber
`faultreiber` generates a parser library in C for a structured file format. The input is an XML file that describes the format.<br/>
The C source code will be in the form of multiple source and header files. a makefile is also included.<br/>
The generated source code does not include a main.<br/>

## faultreiber XML file
The root node should have two childs, named exactly `READ` and `DEFINITION`(order not important).<br/>
The `READ` node will include the actual structures that the parser will read and can return.<br/>
The `DEFINITION` node includes the definitions for the structures that are aggregate.<br/>
For an explanation of the format for the XML file, let's look at the example XML file under `resources`. The XML file describes the format of a WASM object file:<br/>
Any child node of either `DEFINITION` or `READ` will have to at least have the attributes `name` and `type` defined. The presence of the attribute `count` is optional but if it's not present faultreiber will assume that the count is one. The presence of the attribute `isaggregate` signifies the fact that the data structure is composed of other smaller parts. faultreiber will only read the children of a node that is the child of either the `DEFINITION` or `READ` node(unless a child node has the attribute `conditional` set). If a data structure requires more children then you should add a new node under `DEFINITION` and reference that node from it's parent.<br/>
`count`, `size`, `type` and `condition` attributes can reference a child node of the `DEFINITION` node. To do that, you should use `self::TAG`.<br/>
the tag names of the nodes that are on the same level should be unique. The `name` attribute of the nodes on the same level need to be unique as well.<br/>
tags, needless to say, should follow the naming convention for naming XML nodes. The `name` attributes should follow the C identifier naming convention(if the value of the `name` attribute is invalid in C as as identifier you're going to end up with code that won't even build).<br/>
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

Whether `int128` or `uint128` are defined depends on your the C implementation you are using on your host. If 128-bit integers are not supported or you need to read in bigger integers, you can simply use a smaller int type and increase the `count` attribute accordingly.<br/>
The `FT::conditional` tag for a type means that the actual content of the node will depend on a value. The attribute `condition` will provide what that condition is. The value for the condition should be provided as text for the different nodes that define what the actual contents should be.<br/>
A node referencing another node as the value of its `type` attribute is insensitive to the order in which the nodes appear under their parent node, `DEFINITION`.<br/>
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
Only files that are instantly-decodable(need a single pass) are supported.<br/>
None byte sized raw reads are not supported.<br/>
String reads need to have a size. Currently null-terminated string reads without the size of the string are not supported.<br/>

## makefile
To get a list of the targets the makfile supports you can run its `help` target.<br/>

## TODO
All the items under limitations.<br/>
Figure out what the license of the generated code is.<br/>

## Projects
The list of the projects that use faulreiber:<br/>
* [bruiser](https://github.com/bloodstalker/mutator/tree/master/bruiser)<br/>

## License
`faultreiber` along with the makefile are provided under MIT. I don't know if I have the legal right to license the generated files, but if I do, they are also under MIT as far as I'm concerned.<br/>
