#!/bin/sh

#Author : Sébastien Barré
#(c) 2008, Université catholique de Louvain
# Last modified : May 2008
#This is supposed to be called only from the Makefile.am of this directory.

instr=$1
cgaconfdir=$2

cgatool=../cgatool/cgatool

case $instr in
    "cgadconf")	
	cat >cgad.conf <<EOF
#
# Non-optional
#

# The path of the file containing this host's CGA parameters
# configuration file
# <no default>
cga_params=$cgaconfdir/cgad/params.conf

#If “yes”, sendd will replace all non-
#CGA linklocals with CGAs on startup
#and during operation.
#<Default = yes>
replace_linklocal_addresses=yes
EOF
	;;
    "paramsconf")
	mkdir -p cgad/cga
	#We give the link-local prefix here, because a prefix is required
	#by cgatool. But the generated parameters may be used later to
	#generate a CGA for any prefix. If all prefixes use the default
	#parameters generated here, each prefix will always receive the 
	#same CGA suffix, and if two prefixes differ, the suffixes will also
	#differ (this is the definition from the RFC).
	cat >cgad/params.conf <<EOF
#HBA based config
#----------------
#Replace here with the set of prefixes you want to configure
#hba_set default {
#  2001:6a8:3080:3:: ;
#  2001:6f8:3cf8:4:: ;
#}

#This uses the same parameters as those used by CGA, thus creating
#Hybrid HBA/CGA addresses.
#named default {
#  cga_params $cgaconfdir/cgad/cga/default_CGAPDS.der;
#  cga_priv $cgaconfdir/cgad/cga/default_key.pem;
#  cga_sec 1;
#Selects an HBA set
#  hba_set default;
#Removing this will switch off CGA compatibility
#  cga_compat;
#}

#CGA based config
#-----------------
named default {
  cga_params $cgaconfdir/cgad/cga/default_CGAPDS.der;
  cga_priv $cgaconfdir/cgad/cga/default_key.pem;
  cga_sec 1;
}
EOF
	
	;;
    "install")
	mkdir -p $cgaconfdir/cgad/cga
	#if no key is there, create both the key and the der
        if ! [ -f $cgaconfdir/cgad/cga/default_key.pem ]; then
            cgatool -g -k $cgaconfdir/cgad/cga/default_key.pem -R 1024 \
                -o $cgaconfdir/cgad/cga/default_CGAPDS.der -p fe80:: -s 1
        else
	    #If the key is there but not the der, just regenerate the der,
	    #using the existing key.
            if ! [ -f $cgaconfdir/cgad/cga/default_CGAPDS.der ]; then
                cgatool -g -o $cgaconfdir/cgad/cga/default_CGAPDS.der \
                    -k $cgaconfdir/cgad/cga/default_key.pem -p fe80:: -s 1 
            fi  
        fi
	;;
esac
