dexinfo
=======

A very rudimentary dex file parser

Usage
-----
<pre>
=== dexinfo 0.1 - (c) 2012-2013 Pau Oliva Fora

Usage: dexinfo &lt;file.dex&gt; [options]
 options:
    -V             print verbose information
</pre>

Examples
--------
Dex file conaining a hello world application:
<pre>
$ dexinfo classes.dex 

=== dexinfo 0.1 - (c) 2012-2013 Pau Oliva Fora

[] Dex file: classes.dex

[] DEX magic: 64 65 78 0A 30 33 35 00 
[] DEX version: 035
[] Adler32 checksum: 0x6b7223bc
[] SHA1 signature: fca1af87e410f88d6bbd07852f0819f435222988

[] Number of classes in the archive: 8
[] Class 1 (HelloWorld.java): 1 direct methods, 1 virtual methods
	direct method 1 = &lt;init&gt;
	virtual method 1 = onClick
[] Class 2 (HelloWorld.java): 2 direct methods, 1 virtual methods
	direct method 1 = &lt;init&gt;
	direct method 2 = access$0
	virtual method 1 = onCreate
[] Class 3 (R.java): 1 direct methods, 0 virtual methods
	direct method 1 = &lt;init&gt;
[...]
</pre>

Same file, with verbose information:
<pre>
$ dexinfo classes.dex -V

=== dexinfo 0.1 - (c) 2012-2013 Pau Oliva Fora

[] Dex file: classes.dex

[] DEX magic: 64 65 78 0A 30 33 35 00 
[] DEX version: 035
[] Adler32 checksum: 0x6b7223bc
[] SHA1 signature: fca1af87e410f88d6bbd07852f0819f435222988
[] File size: 3496 bytes
[] DEX Header size: 112 bytes (0x70)
[] Endian Tag: 0x12345678
[] Link size: 0
[] Link offset: 0x0
[] Map list offset: 0xcd8
[] Number of strings in string ID list: 72
[] String ID list offset: 0x70
[] Number of types in the type ID list: 27
[] Type ID list offset: 0x190
[] Number of items in the method prototype ID list: 14
[] Method prototype ID list offset: 0x1fc
[] Number of item in the field ID list: 10
[] Field ID list offset: 0x2a4
[] Number of items in the method ID list: 25
[] Method ID list offset: 0x2f4
[] Number of items in the class definitions list: 8
[] Class definitions list offset: 0x3bc
[] Data section size: 2284 bytes
[] Data section offset: 0x4bc

[] Number of classes in the archive: 8
[] Class 1 (HelloWorld.java): 
        type_descriptor: Lpof/helloworld/HelloWorld$1;
        class_idx=0x12
        access_flags=0x0
        superclass_idx=0xf
        interfaces_off=0x72c
        source_file_idx=0x3
        annotations_off=0x6bc
        class_data_off=0xc63 (3171)
        static_values_off=0x0 (0)
        0 static fields
        1 instance fields
                 field_idx_diff=0x0
                 field_access_flags=0x1010
        1 direct methods
        direct method 1 = &lt;init&gt;
                method_code_off=0x50c
                method_access_flags=0x10000
                class_idx=0x12
                proto_idx=0xd
        1 virtual methods
        virtual method 1 = onClick
                method_code_off=0x528
                method_access_flags=0x1
                class_idx=0x12
                proto_idx=0xb
[] Class 2 (HelloWorld.java): 
        type_descriptor: Lpof/helloworld/HelloWorld;
        class_idx=0x13
        access_flags=0x1
        superclass_idx=0x1
        interfaces_off=0x0
        source_file_idx=0x3
        annotations_off=0x0
        class_data_off=0xc74 (3188)
        static_values_off=0x0 (0)
        0 static fields
        2 instance fields
                 field_idx_diff=0x1
                 field_access_flags=0x2
                 field_idx_diff=0x1
                 field_access_flags=0x2
        2 direct methods
        direct method 1 = &lt;init&gt;
                method_code_off=0x59c
                method_access_flags=0x10001
                class_idx=0x13
                proto_idx=0x7
        direct method 2 = access$0
                method_code_off=0x5b4
                method_access_flags=0x1008
                class_idx=0x13
                proto_idx=0x3
        1 virtual methods
        virtual method 1 = onCreate
                method_code_off=0x5cc
                method_access_flags=0x1
                class_idx=0x13
                proto_idx=0x9
[] Class 3 (R.java): 
        type_descriptor: Lpof/helloworld/R$attr;
        class_idx=0x14
        access_flags=0x11
        superclass_idx=0xf
        interfaces_off=0x0
        source_file_idx=0x22
        annotations_off=0x6cc
        class_data_off=0xc8b (3211)
        static_values_off=0x0 (0)
        0 static fields
        0 instance fields
        1 direct methods
        direct method 1 = &lt;init&gt;
                method_code_off=0x62c
                method_access_flags=0x10001
                class_idx=0x14
                proto_idx=0x7
        0 virtual methods
[...]
</pre>
