#!/usr/bin/python

import os
from string import Template
import sys
import re

if len(sys.argv) != 2:
   print "need the name of the new project"
   sys.exit(1)

proj_name = sys.argv[1]
top_make_templ = 'all:\n\t@$$(MAKE) -s -C ribs2\n\t@echo "[${proj_name}] build"\n\t@$$(MAKE) -s -C ${proj_name}/src\nclean:\n\t@$$(MAKE) -s -C ribs2 clean\n\t@echo "[${proj_name}] clean"\n\t@$$(MAKE) -s -C ${proj_name}/src clean'
proj_make_templ = 'TARGET=${proj_name}\n\nSRC=${proj_name}.c\t# list of source files\n\nCFLAGS+= -I ../../ribs2/include\nLDFLAGS+= -L ../../ribs2/lib -lribs2\n\ninclude ../../ribs2/make/ribs.mk'

def get_top_dir():
   paths = os.getcwd().split('/')
   while len(paths) > 1:
      if os.path.isdir('/'.join(paths) + '/ribs2'):
         return '/'.join(paths)
      paths.pop(-1)
   return None

def append_proj(makefile, proj_name):
   fd = open(makefile, 'rw+')
   contents = fd.read()
   fd.close()
   m = re.search(r'((?:.*\n)?all:.*?\n)([^\t](?:.*\nclean:|lean:).*?)($|(?:\n[^\t$].*))', contents, re.DOTALL)
   if not m:
      print "no match"
      return
   add_all = '\t@echo "['+proj_name+'] build"\n\t@$(MAKE) -s -C '+proj_name+'/src\n'
   add_clean = '\n\t@echo "['+proj_name+'] clean"\n\t@$(MAKE) -s -C '+proj_name+'/src clean\n'
   fd = open(makefile, 'w')
   fd.write(m.group(1))
   fd.write(add_all)
   fd.write(m.group(2))
   fd.write(add_clean)
   fd.write(m.group(3))
   fd.close()

top_dir = get_top_dir()
proj_dir = top_dir+"/"+proj_name+"/src"
top_make = top_dir+"/Makefile"
os.system("mkdir -p "+proj_dir)
if os.path.exists(top_make):
   append_proj(top_make, proj_name)
else:
   fd = open(top_make, 'w')
   fd.write(Template(top_make_templ).substitute(proj_name=proj_name))
   fd.close()
proj_make = proj_dir+"/Makefile"
fd = open(proj_make, 'w')
fd.write(Template(proj_make_templ).substitute(proj_name=proj_name))
fd.close()

proj_src = proj_dir+'/'+proj_name+'.c'
fd = open(proj_src, 'w')
fd.write('int main(void) {\n    return 0;\n}')
fd.close()
