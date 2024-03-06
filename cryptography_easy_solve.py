#!/usr/bin/env python3
from pwn import *

EMPTY = -1

def generate_given_step(iteration_power, iteration, x0, a, c,  x1, x2, x3, x4, x5, x0_first_bit, a_first_bit, c_first_bit):
    a = iteration_power * a_first_bit + a
    c = iteration_power * c_first_bit + c
    x0 = iteration_power * x0_first_bit + x0

    x1_tmp1 = ((a * x0 ^ c) % (2 ** 64))
    x2_tmp1 = ((a * x1_tmp1 ^ c) % (2 ** 64))
    x3_tmp1 = ((a * x2_tmp1 ^ c) % (2 ** 64))
    x4_tmp1 = ((a * x3_tmp1 ^ c) % (2 ** 64))
    x5_tmp1 = ((a * x4_tmp1 ^ c) % (2 ** 64))
    x6_tmp1 = ((a * x5_tmp1 ^ c) % (2 ** 64))

    x1_tmp = x1_tmp1 % (iteration_power * 2)
    x2_tmp = x2_tmp1 % (iteration_power * 2)
    x3_tmp = x3_tmp1 % (iteration_power * 2)
    x4_tmp = x4_tmp1 % (iteration_power * 2)
    x5_tmp = x5_tmp1 % (iteration_power * 2)
    x6_tmp = x6_tmp1 % (iteration_power * 2)

    # Sprawdzamy, czy dany zestaw bitów x0, a i c spełnia warunki zadania,
    # jeśli tak, kontynuujemy rekurencję, jeśli nie, zwracamy pustą wartość (-1)
    # na koniec bierzemy pod uwagę wartość maksymalną z wszystkich możliwości, w ten sposób
    # wybieramy x6 zamiast pustych -1. Czasem ten kod nie wypisze flagi, gdyż będzie więcej
    # niż 1 możliwa odpowiedź, a on nie wypisze najlepszej z nich, jednak wtedy wystarczy
    # uruchomić go ponownie, a wtedy powinien wypisać flagę.
    if (x1_tmp == (x1 % (iteration_power * 2)) and 
        x2_tmp == (x2 % (iteration_power * 2)) and 
        x3_tmp == (x3 % (iteration_power * 2)) and
        x4_tmp == (x4 % (iteration_power * 2)) and
        x5_tmp == (x5 % (iteration_power * 2))):

        if (iteration == 63):
            return x6_tmp
        else:
            return generate_next(iteration_power * 2, iteration + 1, x0, a, c, x1, x2, x3, x4, x5)
    else:
        return EMPTY


# Ze względu na ograniczoną liczbę dopuszczalnych wartości, możemy
# użyć brutalnej siły i bit po bicie (idąc od najmniej znaczącego), odtwarzać wszystkie dopuszczalne wartości
# x0, a i c i odrzucać wszystkie opcje niespełniające warunków, czyli nie mogące wygenerować znanych
# nam x1, x2, x3, x4, x5. 
def generate_next(iteration_power, iteration, x0, a, c, x1, x2, x3, x4, x5):
    v1 = generate_given_step(iteration_power,iteration, x0, a, c,  x1, x2, x3, x4, x5, 0, 0, 0)
    v2 = generate_given_step(iteration_power,iteration, x0, a, c,  x1, x2, x3, x4, x5, 0, 0, 1)
    v3 = generate_given_step(iteration_power,iteration, x0, a, c,  x1, x2, x3, x4, x5, 0, 1, 0)
    v4 = generate_given_step(iteration_power,iteration, x0, a, c,  x1, x2, x3, x4, x5, 0, 1, 1)
    v5 = generate_given_step(iteration_power,iteration, x0, a, c,  x1, x2, x3, x4, x5, 1, 0, 0)
    v6 = generate_given_step(iteration_power,iteration, x0, a, c,  x1, x2, x3, x4, x5, 1, 0, 1)
    v7 = generate_given_step(iteration_power,iteration, x0, a, c,  x1, x2, x3, x4, x5, 1, 1, 0)
    v8 = generate_given_step(iteration_power,iteration, x0, a, c,  x1, x2, x3, x4, x5, 1, 1, 1)
    
    return max(v1, v2, v3, v4, v5, v6, v7, v8)

def conn(name, port):
    r = remote(name, port)
    # Wybieramy NCG challenge
    r.sendlineafter(b'>', b'1')

    x1 = r.recvuntil(b'\n').decode()
    x2 = r.recvuntil(b'\n').decode()
    x3 = r.recvuntil(b'\n').decode()
    x4 = r.recvuntil(b'\n').decode()
    x5 = r.recvuntil(b'\n').decode()

    # Kontrolnie wypisujemy uzyskane wartości
    print(x1)
    print(x2)
    print(x3)
    print(x4)
    print(x5)

    y = generate_next(1, 0, 0, 0, 0, int(x1), int(x2), int(x3), int(x4), int(x5))
    # Kontrolnie wypisujemy uzyskaną wartość
    print("Wysyłana wartość: " + str(y))
    r.sendlineafter(b'What\'s next?', str(y))
    # Uzyskana flaga to: "flag{still-not-a-csprng}""
    flag = r.recvuntil(b'}').decode()
    print("Flaga:")
    print(flag)

    return r


def main():

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <address> <port>")
        sys.exit(1)

    arg1 = sys.argv[1]
    arg2 = sys.argv[2]

    if arg1 == "local":
        arg1 = "localhost"

    r = conn(arg1, arg2)
    r.interactive()


if __name__ == "__main__":
    main()