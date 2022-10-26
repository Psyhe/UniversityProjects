#!/bin/bash
prog=$1
dir=$2

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'



for f in $dir/*.in
do  
  $prog < $f 2> progerror 1> progout
  EXITCODE=$?
  if (($EXITCODE == 1 || $EXITCODE==0))
  then
      printf "${f%.in} ${GREEN}EXITCODE:$EXITCODE${NC}\n"
    if diff progout "${f%.in}.out" >/dev/null 2>&1    
    then
      printf "${f%.in}.out ${GREEN}PASSED${NC}\n"
    else 
      printf "${f%.in}.out ${RED}FAILED${NC}\n"
      continue
    fi

    if diff progerror "${f%.in}.err" >/dev/null 2>&1    
    then
        printf "${f%.in}.err ${GREEN}PASSED${NC}\n"
    else 
        printf "${f%.in}.err ${RED}FAILED${NC}\n" #Due to different interpretations of errors, I check valgrind even if there is inaccurate error.
    fi

    valgrind --error-exitcode=123 --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all ./$prog < $f 2>valgrindoutput
    EXITCODE_VALGRIND=$?

    if (($EXITCODE_VALGRIND==123))
    then
      printf "valgrind for ${f%.in} ${RED}FAILED${NC}\n"
      cat valgrindoutput
    else
      printf "valgrind for ${f%.in} ${GREEN}PASSED${NC}\n"
    fi
  else 
    printf "${f%.in} ${RED}WRONG EXITCODE: $EXITCODE${NC}\n"
  fi

done

rm progout
rm progerror
rm valgrindoutput