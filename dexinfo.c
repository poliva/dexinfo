/*
 * dexinfo - a very rudimentary dex file parser
 *
 * Copyright (C) 2012-2013 Pau Oliva Fora (@pof)
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>

#define VERSION "0.1"

typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;

typedef struct {
	char dex[3];
	char newline[1];
	char ver[3];
	char zero[1];
} dex_magic;

typedef struct {
	dex_magic magic;
	u4 checksum[1];
	unsigned char signature[20];
	u4 file_size[1];
	u4 header_size[1];
	u4 endian_tag[1];
	u4 link_size[1];
	u4 link_off[1];
	u4 map_off[1];
	u4 string_ids_size[1];
	u4 string_ids_off[1];
	u4 type_ids_size[1];
	u4 type_ids_off[1];
	u4 proto_ids_size[1];
	u4 proto_ids_off[1];
	u4 field_ids_size[1];
	u4 field_ids_off[1];
	u4 method_ids_size[1];
	u4 method_ids_off[1];
	u4 class_defs_size[1];
	u4 class_defs_off[1];
	u4 data_size[1];
	u4 data_off[1];
} dex_header;

typedef struct {
	u4 class_idx[1];
	u4 access_flags[1];
	u4 superclass_idx[1];
	u4 interfaces_off[1];
	u4 source_file_idx[1];
	u4 annotations_off[1];
	u4 class_data_off[1];
	u4 static_values_off[1];
} class_def_struct;

typedef struct {
	u2 class_idx[1];
	u2 proto_idx[1];
	u4 name_idx[1];
} method_id_struct;

typedef struct {
	u4 string_data_off[1];
} string_id_struct;

typedef struct {
	u4 descriptor_idx[1];
} type_id_struct;

int readUnsignedLeb128(u1** pStream)
{
/* taken from dalvik's libdex/Leb128.h */
    u1* ptr = *pStream;
    int result = *(ptr++);

    if (result > 0x7f) {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    /*
                     * Note: We don't check to see if cur is out of
                     * range here, meaning we tolerate garbage in the
                     * high four-order bits.
                     */
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }

    *pStream = ptr;
    return result;
}

int uleb128_value(u1* pStream)
{
    u1* ptr = pStream;
    int result = *(ptr++);

    if (result > 0x7f) {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    /*
                     * Note: We don't check to see if cur is out of
                     * range here, meaning we tolerate garbage in the
                     * high four-order bits.
                     */
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }
    return result;
}


size_t len_uleb128(unsigned long n)
{
    static unsigned char b[32];
    size_t i;

    i = 0;
    do
    {
        b[i] = n & 0x7F;
        if (n >>= 7)
            b[i] |= 0x80;
    }
    while (b[i++] & 0x80);
    return i;
}

void help_show_message()
{
	fprintf(stderr, "Usage: dexinfo <file.dex> [options]\n");
	fprintf(stderr, " options:\n");
	fprintf(stderr, "    -V             print verbose information\n");
}

int main(int argc, char *argv[])
{
	char *dexfile;
	FILE *input;
	size_t offset, offset2;
	ssize_t len;
	int i,c;
	int DEBUG=0;

	int static_fields_size;
	int instance_fields_size;
	int direct_methods_size;
	int virtual_methods_size; 

	int field_idx_diff;
	int field_access_flags;

	int method_idx_diff;
	int method_access_flags;
	int method_code_off;

	int key;

	dex_header header;
	class_def_struct class_def_item;
	u1* buffer;
	u1* buf;
	u1* buffer_pos;
	u1* str=NULL;
	u1 size[1]; // XXX this will break if size is > u1... because size is uleb128

	method_id_struct method_id_item;
	method_id_struct* method_id_list;

	string_id_struct string_id_item;
	string_id_struct* string_id_list;

	type_id_struct type_id_item;
	type_id_struct* type_id_list;

	int size_uleb, size_uleb_value;

	printf ("\n=== dexinfo %s - (c) 2012-2013 Pau Oliva Fora\n\n", VERSION);

	if (argc < 2) {
		help_show_message();
		return 1;
	}

	dexfile=argv[1];
	input = fopen(dexfile, "rb");
	if (input == NULL) {
		fprintf(stderr, "ERROR: Can't open dex file!\n");
		perror(dexfile);
		exit(1);
	}

        while ((c = getopt(argc, argv, "V")) != -1) {
                switch(c) {
     		case 'V':
			DEBUG=1;
			break;
                default:
                        help_show_message();
                        return 1;
                }
        }

	/* print dex header information */
        printf ("[] Dex file: %s\n\n",dexfile);

	memset(&header, 0, sizeof(header));
	memset(&class_def_item, 0, sizeof(class_def_item));

	fread(&header, 1, sizeof(header), input);

	printf ("[] DEX magic: ");
	for (i=0;i<3;i++) printf("%02X ", header.magic.dex[i]);
	printf("%02X ", *header.magic.newline);
	for (i=0;i<3;i++) printf("%02X ", header.magic.ver[i]);
	printf("%02X ", *header.magic.zero);
	printf ("\n");

	if ( (strncmp(header.magic.dex,"dex",3) != 0) || 
	     (strncmp(header.magic.newline,"\n",1) != 0) || 
	     (strncmp(header.magic.zero,"\0",1) != 0 ) ) {
		fprintf (stderr, "ERROR: not a dex file\n");
		fclose(input);
		exit(1);
	}

	printf ("[] DEX version: %s\n", header.magic.ver);
	if (strncmp(header.magic.ver,"035",3) != 0) {
		fprintf (stderr,"Warning: Dex file version != 035\n");
	}

	printf ("[] Adler32 checksum: 0x%x\n", *header.checksum);

	printf ("[] SHA1 signature: ");
	for (i=0;i<20;i++) printf("%02x", header.signature[i]);
	printf("\n");

	if (DEBUG) {
		printf ("[] File size: %d bytes\n", *header.file_size);
		printf ("[] DEX Header size: %d bytes (0x%x)\n", *header.header_size, *header.header_size);
	}

	if (*header.header_size != 0x70) {
		fprintf (stderr,"Warning: Header size != 0x70\n");
	}

	if (DEBUG) printf("[] Endian Tag: 0x%x\n", *header.endian_tag);
	if (*header.endian_tag != 0x12345678) {
		fprintf (stderr,"Warning: Endian tag != 0x12345678\n");
	}

	if (DEBUG) {
		printf("[] Link size: %d\n", *header.link_size);
		printf("[] Link offset: 0x%x\n", *header.link_off);
		printf("[] Map list offset: 0x%x\n", *header.map_off);
		printf("[] Number of strings in string ID list: %d\n", *header.string_ids_size);
		printf("[] String ID list offset: 0x%x\n", *header.string_ids_off);
		printf("[] Number of types in the type ID list: %d\n", *header.type_ids_size);
		printf("[] Type ID list offset: 0x%x\n", *header.type_ids_off);
		printf("[] Number of items in the method prototype ID list: %d\n", *header.proto_ids_size);
		printf("[] Method prototype ID list offset: 0x%x\n", *header.proto_ids_off);
		printf("[] Number of item in the field ID list: %d\n", *header.field_ids_size);
		printf("[] Field ID list offset: 0x%x\n", *header.field_ids_off);
		printf("[] Number of items in the method ID list: %d\n", *header.method_ids_size);
		printf("[] Method ID list offset: 0x%x\n", *header.method_ids_off);
		printf("[] Number of items in the class definitions list: %d\n", *header.class_defs_size);
		printf("[] Class definitions list offset: 0x%x\n", *header.class_defs_off);
		printf("[] Data section size: %d bytes\n", *header.data_size);
		printf("[] Data section offset: 0x%x\n", *header.data_off);
	}

	printf("\n[] Number of classes in the archive: %d\n", *header.class_defs_size);

	/* parse the strings */
	string_id_list = malloc(*header.string_ids_size*sizeof(string_id_item));
	fseek(input, *header.string_ids_off, SEEK_SET);
	fread(string_id_list, 1, *header.string_ids_size*sizeof(string_id_item), input);

	/* parse the types */
	type_id_list = malloc(*header.type_ids_size*sizeof(type_id_item));
	fseek(input, *header.type_ids_off, SEEK_SET);
	fread(type_id_list, 1, *header.type_ids_size*sizeof(type_id_item), input);

	/* parse methods */
	method_id_list = malloc(*header.method_ids_size*sizeof(method_id_item));
	fseek(input, *header.method_ids_off, SEEK_SET);
	fread(method_id_list, 1, *header.method_ids_size*sizeof(method_id_item), input);

#if 0
	/* strings */
	for (i=0;i < (*header.string_ids_size)*(sizeof(string_id_item)) ;i+=4) {
		printf("string_id_list[%d]=%x\n", i/4, *string_id_list[i/4].string_data_off);
	}

	/* methods */
	for (i=0;i<sizeof(method_id_item)*(*header.method_ids_size);i+=8) {
		printf ("method_id_list[%d]class=%x\n", i/8, *method_id_list[i/8].class_idx);
		printf ("method_id_list[%d]proto=%x\n", i/8, *method_id_list[i/8].proto_idx);
		printf ("method_id_list[%d]name=%x\n\n", i/8, *method_id_list[i/8].name_idx);
	}
#endif

	for (c=1; c <= (int)*header.class_defs_size; c++) {

		// change the position to the class_def_struct of each class
		offset = *header.class_defs_off + ((c-1)*sizeof(class_def_item));
		fseek(input, offset, SEEK_SET);

		printf("[] Class %d ", c);

		fread(&class_def_item, 1, sizeof(class_def_item), input);

		/* print class filename */
		if (*class_def_item.source_file_idx != 0xffffffff) {
			offset2=*string_id_list[*class_def_item.source_file_idx].string_data_off;
			fseek(input, offset2, SEEK_SET);
			fread(size, 1, sizeof(size), input);
			str = malloc(size[0] * sizeof(u1)+1);
			fread(str, 1, size[0], input);
			str[size[0]]='\0';
			printf ("(%s): ", str);
			free(str);
			str=NULL;
		} else {
			printf ("(No index): ");
		}

		if (DEBUG) {
			printf("\n");

			/* print type id */
			offset2=*string_id_list[*type_id_list[*class_def_item.class_idx].descriptor_idx].string_data_off;
			fseek(input, offset2, SEEK_SET);
			fread(size, 1, sizeof(size), input);
			str = malloc(size[0] * sizeof(u1)+1);
			fread(str, 1, size[0], input);
			str[size[0]]='\0';
			printf ("\ttype_descriptor: %s\n", str);
			free(str);
			str=NULL;

			printf("\tclass_idx=0x%x\n", *class_def_item.class_idx);
			printf("\taccess_flags=0x%x\n", *class_def_item.access_flags);
			printf("\tsuperclass_idx=0x%x\n", *class_def_item.superclass_idx);
			printf("\tinterfaces_off=0x%x\n", *class_def_item.interfaces_off);
			printf("\tsource_file_idx=0x%x\n", *class_def_item.source_file_idx);
			printf("\tannotations_off=0x%x\n", *class_def_item.annotations_off);
			printf("\tclass_data_off=0x%x (%d)\n", *class_def_item.class_data_off, *class_def_item.class_data_off);
			printf("\tstatic_values_off=0x%x (%d)\n", *class_def_item.static_values_off, *class_def_item.static_values_off);
		}

		// change position to class_data_off
		if (*class_def_item.class_data_off == 0) {
			if (DEBUG) {
				printf ("\t0 static fields\n");
				printf ("\t0 instance fields\n");
				printf ("\t0 direct methods\n");
			} else {
				printf ("0 direct methods, 0 virtual methods\n");
			}
			continue;
		} else {
			offset = *class_def_item.class_data_off;
			fseek(input, offset, SEEK_SET);
		}

		len = *header.map_off - offset;
		if (len < 1) {
			len = *header.file_size - offset;
			if (len < 1) {
				fprintf(stderr, "ERROR: invalid file length in dex header?\n");
				fclose(input);
				exit(1);
			}
		}

		buffer = malloc(len * sizeof(u1));
		if (buffer == NULL) {
			fprintf(stderr, "ERROR: could not allocate memory!\n");
			fclose(input);
			exit(1);
		}
		buffer_pos=buffer;
		memset(buffer, 0, len);
		fread(buffer, 1, len, input);

		// from now on we continue on memory, as we have to parse uleb128
		static_fields_size = readUnsignedLeb128(&buffer);
		instance_fields_size = readUnsignedLeb128(&buffer);
		direct_methods_size = readUnsignedLeb128(&buffer);
		virtual_methods_size = readUnsignedLeb128(&buffer);

		if (DEBUG) printf ("\t%d static fields\n", static_fields_size);

		for (i=0;i<static_fields_size;i++) {
			field_idx_diff = readUnsignedLeb128(&buffer);
			field_access_flags = readUnsignedLeb128(&buffer);
			if (DEBUG) {
				printf ("\t\t field_idx_diff=0x%x\n", field_idx_diff);
				printf ("\t\t field_access_flags=0x%x\n", field_access_flags);
			}
		}

		if (DEBUG) printf ("\t%d instance fields\n", instance_fields_size);

		for (i=0;i<instance_fields_size;i++) {
			field_idx_diff = readUnsignedLeb128(&buffer);
			field_access_flags = readUnsignedLeb128(&buffer);
			if (DEBUG) {
				printf ("\t\t field_idx_diff=0x%x\n", field_idx_diff);
				printf ("\t\t field_access_flags=0x%x\n", field_access_flags);
			}
		}

		if (!DEBUG) printf ("%d direct methods, %d virtual methods\n", direct_methods_size, virtual_methods_size);


		if (DEBUG) printf ("\t%d direct methods\n", direct_methods_size);

		key=0;
		for (i=0;i<direct_methods_size;i++) {
			method_idx_diff = readUnsignedLeb128(&buffer);
			method_access_flags = readUnsignedLeb128(&buffer);
			method_code_off = readUnsignedLeb128(&buffer);

			/* methods */
			if (key == 0) key=method_idx_diff;
			else key += method_idx_diff;

			u2 class_idx=*method_id_list[key].class_idx;
			u2 proto_idx=*method_id_list[key].proto_idx;
			u4 name_idx=*method_id_list[key].name_idx;

			/* print method name */
			offset2=*string_id_list[name_idx].string_data_off;
			fseek(input, offset2, SEEK_SET);

			buf = malloc(10 * sizeof(u1));
			fread(buf, 1, sizeof(buf), input);
			size_uleb_value = uleb128_value(buf);
			size_uleb=len_uleb128(size_uleb_value);
			str = malloc(size_uleb_value * sizeof(u1)+1);
			// offset2: on esta el tamany (size_uleb_value) en uleb32 de la string, seguit de la string
			fseek(input, offset2+size_uleb, SEEK_SET);
			fread(str, 1, size_uleb_value, input);
			str[size_uleb_value]='\0';

			printf ("\tdirect method %d = %s\n",i+1, str);
			free(str);
			str=NULL;
			if (DEBUG) {
				printf("\t\tmethod_code_off=0x%x\n", method_code_off);
				printf("\t\tmethod_access_flags=0x%x\n", method_access_flags);
				printf("\t\tclass_idx=0x%x\n", class_idx);
				printf("\t\tproto_idx=0x%x\n", proto_idx);
			}
		}

		if (DEBUG) printf ("\t%d virtual methods\n", virtual_methods_size);

		key=0;
		for (i=0;i<virtual_methods_size;i++) {
			method_idx_diff = readUnsignedLeb128(&buffer);
			method_access_flags = readUnsignedLeb128(&buffer);
			method_code_off = readUnsignedLeb128(&buffer);

			/* methods */
			if (key == 0) key=method_idx_diff;
			else key += method_idx_diff;

			u2 class_idx=*method_id_list[key].class_idx;
			u2 proto_idx=*method_id_list[key].proto_idx;
			u4 name_idx=*method_id_list[key].name_idx;
			
			/* print method name */
			offset2=*string_id_list[name_idx].string_data_off;
			fseek(input, offset2, SEEK_SET);
			fread(size, 1, sizeof(size), input);
			str = malloc(size[0] * sizeof(u1)+1);
			fread(str, 1, size[0], input);
			str[size[0]]='\0';
			printf ("\tvirtual method %d = %s\n",i+1, str);
			free(str);
			str=NULL;
			if (DEBUG) {
				printf("\t\tmethod_code_off=0x%x\n", method_code_off);
				printf("\t\tmethod_access_flags=0x%x\n", method_access_flags);
				printf("\t\tclass_idx=0x%x\n", class_idx);
				printf("\t\tproto_idx=0x%x\n", proto_idx);
			}

		}

		free(buffer_pos);
	}

	free(type_id_list);
	free(method_id_list);
	free(string_id_list);

	fclose(input);
	return 0;
}
