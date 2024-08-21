/* #undef DEBUG */
#define DB_ROOT "etc/CondEncCPP.d"

// the configured options and settings for Tutorial
#define condenccpp_VERSION_MAJOR 
#define condenccpp_VERSION_MINOR 
#define condenccpp_VERSION_PATCH 

#define CAFILE ""
#define OLD_CAFILE ""
#define UPLOAD_URL "https://typtop.info/submit"
#define PARTICIPATION_FILE "/usr/local/etc/CondEncCPP.d/participate"


#ifdef WIN32
#define OS_SEP '\\'
#define USERDB_LOC "/somewhere/I/don't/know/"
#else
#define USERDB_LOC "/usr/local/etc/condenccpp.d/"
#define OS_SEP '/'
#endif
