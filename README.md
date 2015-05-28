# logfudge
LogFudge for linux

INSTALL:
  autoreconf -i
  ./configure 
  make

USAGE
  Collecting mode
  ./logfudge -c data.lfg P arg1 arg2 arg3
  
  Recreate mode
  ./logfudge -r data.lfg
