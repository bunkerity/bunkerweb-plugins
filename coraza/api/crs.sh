#!/bin/bash

function git_secure_clone() {
	repo="$1"
	commit="$2"
	folder="$(echo "$repo" | sed -E "s@https://github.com/.*/(.*)\.git@\1@")"
	if [ ! -d "${folder}" ] ; then
		output="$(git clone "$repo" "${folder}" 2>&1)"
		# shellcheck disable=SC2181
		if [ $? -ne 0 ] ; then
			echo "❌ Error cloning $1"
			echo "$output"
			exit 1
		fi
		old_dir="$(pwd)"
		cd "${folder}" || exit 1
		output="$(git checkout "${commit}^{commit}" 2>&1)"
		# shellcheck disable=SC2181
		if [ $? -ne 0 ] ; then
			echo "❌ Commit hash $commit is absent from repository $repo"
			echo "$output"
			exit 1
		fi
		cd "$old_dir" || exit 1
		output="$(rm -rf "${folder}/.git")"
		# shellcheck disable=SC2181
		if [ $? -ne 0 ] ; then
			echo "❌ Can't delete .git from repository $repo"
			echo "$output"
			exit 1
		fi
	else
		echo "⚠️ Skipping clone of $repo because target directory is already present"
	fi
}

function do_and_check_cmd() {
	if [ "$CHANGE_DIR" != "" ] ; then
		cd "$CHANGE_DIR" || exit 1
	fi
	output=$("$@" 2>&1)
	ret="$?"
	# shellcheck disable=SC2181
	if [ $ret -ne 0 ] ; then
		echo "❌ Error from command : $*"
		echo "$output"
		exit $ret
	fi
	#echo $output
	return 0
}

function remove_coreruleset(){
	dir="coreruleset"
	if [ -d "$dir" ] ; then
		output="$(rm -rf $dir)"
		echo "$output"
		exit 1
	else
		echo "⚠️ Skipping  remove of $dir because target directory do not exist"
	fi
}

# CRS v4
echo "ℹ️ Download CRS or Remove CRS"
if [[ "$1" == "Remove" ]]; then
  remove_coreruleset
elif [[ "$1" == "Download" ]]; then
	git_secure_clone "https://github.com/coreruleset/coreruleset.git" "2b92d53ea708babbca8da06cd13decffbc9e31b5"
else
	echo "❌ Error wrong argument : $1 try Remove or Download"
fi
