dnl Build description for libar
dnl 
dnl NO USER SERVICEABLE PARTS INSIDE
dnl See the package README file for details.

include(confBUILDTOOLSDIR`/M4/switch.m4')

define(`confREQUIRE_LIBSM', `true')

define(`confMT', `true')

bldPRODUCT_START(`library', `libar')
define(`bldSOURCES', `ar.c manual.c ')
bldPRODUCT_END

bldPRODUCT_START(`manpage', `ar')
define(`bldSOURCES', `ar.3')
bldPRODUCT_END

bldFINISH
