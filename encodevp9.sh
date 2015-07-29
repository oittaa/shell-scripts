#!/bin/sh

# 2015-07-27 Parameters for 2-pass VP9 encoding:
# http://wiki.webmproject.org/ffmpeg/vp9-encoding-guide

if [ $# -eq 0 ]
then
  echo "Please give input files as parameters"
  exit 1
fi

for var in "$@"
do
  if [ ! -f "$var" ]
  then
    echo "File doesn't exist: \"$var\""
    exit 1
  fi
done

LOGDIR=`mktemp -d --tmpdir -- "$(basename $0).XXXXXXXXXX"` || exit 1
trap "rm -r -- \"$LOGDIR\"; exit 1" HUP INT TERM

LOGFILE="${LOGDIR}/stream"
CORES=$(grep -c ^processor /proc/cpuinfo)

for INPUTFILE in "$@"
do
  OUTPUTFILE=$(basename "$INPUTFILE"|sed 's/\.\(avi\|flv\|m4v\|mkv\|mp4\|mpg\|wmv\)$//').webm

  TEMP=$(ffprobe -v error -show_streams "$INPUTFILE")
  WIDTH=$(echo "$TEMP" | sed -n -e 's/^width=//p')
  HEIGHT=$(echo "$TEMP" | sed -n -e 's/^height=//p')
  TEMP=$(ffprobe -v error -show_format "$INPUTFILE")
  BIT_RATE=$(echo "$TEMP" | sed -n -e 's/^bit_rate=//p')

  echo "INPUT: ${WIDTH}x${HEIGHT} ${BIT_RATE}bps \"${INPUTFILE}\""

  if ([ $WIDTH -ge 1920 ] || [ $HEIGHT -ge 1080 ]) && [ $BIT_RATE -ge 6000000 ]
  then
    BR=3M
  elif ([ $WIDTH -ge 1280 ] || [ $HEIGHT -ge 720 ]) && [ $BIT_RATE -ge 4000000 ]
  then
    BR=2M
  elif ([ $WIDTH -ge 640 ] || [ $HEIGHT -ge 480 ]) && [ $BIT_RATE -ge 2000000 ]
  then
    BR=1M
  else
    BR=700k
  fi

  echo "OUTPUT: ${WIDTH}x${HEIGHT} ${BR}bps \"${OUTPUTFILE}\""
  ffmpeg -i "$INPUTFILE" -c:v libvpx-vp9 -pass 1 -b:v "$BR" -keyint_min 25 -g 250 -threads "$CORES" -speed 4 -tile-columns 6 -frame-parallel 1 -auto-alt-ref 1 -lag-in-frames 25  -an -passlogfile "$LOGFILE" -f webm -y /dev/null
  ffmpeg -i "$INPUTFILE" -c:v libvpx-vp9 -pass 2 -b:v "$BR" -keyint_min 25 -g 250 -threads "$CORES" -speed 1 -tile-columns 6 -frame-parallel 1 -auto-alt-ref 1 -lag-in-frames 25  -c:a libopus -b:a 64k -passlogfile "$LOGFILE" -f webm -y -- "$OUTPUTFILE"
  rm -- "${LOGFILE}"-*.log
done
rm -r -- "$LOGDIR"
