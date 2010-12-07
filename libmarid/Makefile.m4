include(confBUILDTOOLSDIR`/M4/switch.m4')

bldPRODUCT_START(`library', `libmarid')
define(`bldSOURCES', `sm-marid-address.c sm-marid-arena.c sm-marid.c sm-marid-dir-a.c sm-marid-dir-all.c sm-marid-dir-exists.c sm-marid-dir-include.c sm-marid-dir-ip.c sm-marid-dir-ptr.c sm-marid-dns.c sm-marid-domain.c sm-marid-evaluate.c sm-marid-fqdn.c sm-marid-ip.c sm-marid-mod.c sm-marid-mod-exp.c sm-marid-mod-redirect.c sm-marid-record.c sm-marid-scan.c sm-marid-util.c sm-marid-log.c sm-marid-frame.c ')
bldPRODUCT_END


bldFINISH
