#/usr/bin/bash
echo 'Install apk-hunter'
echo ' -> install gem'
echo ' -> gem::html-table'
gem install html-table
echo ' -> gem::colorize'
gem install colorize
echo ' -> set command'
MYPWD=`pwd`
ruby apkhunter.rb

echo 'Finish. run a dhunter'