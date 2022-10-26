/*
"Poziomka"

Projekt ten wykonuje ruchy Prawego w odpowiedzi na ruchy Lewego
w grze w Poziomkę. Program symuluje wszystkie możliwe ruchy
Prawego po czym wybiera ten, który maksymalizuje ocenę planszy
Prawego. Jeśli jest kilka ruchów spełniających ten warunek, wybiera
taki, który ma numer WYBOR % n, gdzie WYBOR to zdefiniowana stała,
a n to liczba opcji dobrych ruchów możliwych do wykonania. Gra kończy
się, gdy któryś z graczy się podda, wówczas program wypisze '.'
i/lub zakończy działanie.
autor: Maria Wysogląd
*/
#include <stdio.h>

#ifndef POLA
#define POLA 5
#endif

#ifndef WIERSZE
#define WIERSZE 26
#endif

#ifndef KOLUMNY
#define KOLUMNY 26
#endif

#ifndef WYBOR
#define WYBOR 1000
#endif
/* Aktualny stan planszy trzymam w tablicy plansza[WIERSZE][KOLUMNY],
przy czym zarówno wiersze jak i kolumny numeruję od 0 (przy wczytywaniu
dokonuję konwersji z 'A' lub 'a' na 0, 'B' lub 'b' na 1 itd.).
W tablica_opcji zapisuje początkową współrzędną każdego klocka,
który może być położony w danym ruchu i spełnia zasadę maksymalizacji
oceny Prawego. */

void wczytywanie(int *kropka, int plansza[WIERSZE][KOLUMNY]) {
    int kolumna_lewy;
    int wiersz_lewy;

    kolumna_lewy = getchar();
    if (kolumna_lewy == '.') {
        *kropka = 1;
    }
    else if (kolumna_lewy != '-') {
        kolumna_lewy -= 'A';
        /* Odjęcie - 'A' pozwala na konwersję dużych liter
        na liczbę w taki sposób, że A zostaje przekształcone
        na 0, B na 1 itd. */
        wiersz_lewy = getchar() - 'a';
        // Analogicznie muszą zostać przekształcone małe litery.
        for (int i = wiersz_lewy; i < (wiersz_lewy + POLA); i++) {
            plansza[i][kolumna_lewy] = 1;
        }
    }

    getchar();
    /* Na koniec musimy przesunąć getchar() tak, by w następnej
    rundzie wczytywał numer i-tej kolumny, a nie enter; getchar()
    na końcu funkji wczytuje enter i nic się z nim dalej nie
    dzieje. */
}

void wpisz_klocek_prawy(int wiersz, int kolumna, int plansza[WIERSZE][KOLUMNY]) {
    // Wpisuje dany klocek na planszę.
    for (int i = kolumna; i < (kolumna + POLA); i++) {
        plansza[wiersz][i] = 1;
    }
}

void usun_klocek_prawy(int wiersz, int kolumna, int plansza[WIERSZE][KOLUMNY]) {
    // Usuwa z planszy klocek po symulacji.
    for (int i = kolumna; i < (kolumna + POLA); i++) {
        plansza[wiersz][i] = 0;
    }
}

void wypisywanie(int wiersz_prawy, int kolumna_prawy) {
    char wiersz = (char)wiersz_prawy + 'a';
    char kolumna = (char)kolumna_prawy + 'A';
    /* Numer wiersza i kolumny musi być skonwertowany na char,
    aby uzyskać małą literę trzeba dodać 'a', a aby dużą 'A'
    W ten sposób 0 może być skonwertowane na odpowiednio
    a lub A, 1 na b lub B itd. */

    printf("%c%c\n", wiersz, kolumna);
}

int ocena_prawego(int plansza[WIERSZE][KOLUMNY]) {
    // Ile klocków może maksymalnie jeszcze położyć prawy.
    int liczba_pol = 0;
    int licznik = 0;
    // Jest wskaźnikiem długości segmentu zerowego.

    for (int j = 0; j < WIERSZE; j++) {
        for (int i = 0; i < KOLUMNY; i++) {
            if (plansza[j][i] == 0){
                licznik++;
            }
            else if (plansza[j][i] == 1) {
                liczba_pol += licznik/POLA;
                /* Można dostawić w danym wierszu tyle pól,
                ile wynosi podłoga z licznik/POLA. */
                licznik = 0;
            }  
        }

        liczba_pol += licznik/POLA;
        // Na końcu wiersza również trzeba zaktualizować liczbę klocków.
        licznik = 0;
    }

    return liczba_pol;
}

int ocena_lewego(int plansza[WIERSZE][KOLUMNY]) {
    // Ile klocków może maksymalnie jeszcze położyć lewy.
    int liczba_pol = 0;
    int licznik = 0;
    // Jest wskaźnikiem długości segmentu zerowego.

    for (int j = 0; j < KOLUMNY; j++) {
        for (int i = 0; i < WIERSZE; i++) {
            if (plansza[i][j] == 0){
                licznik++;
            }
            else if (plansza[i][j] == 1) {
                liczba_pol += licznik/POLA;
                /* Można dostawić w danym wierszu tyle pól,
                ile wynosi podłoga z licznik/POLA. */
                licznik = 0;
            }   
        }
        
        liczba_pol += licznik/POLA;
        // Na końcu wiersza również trzeba zaktualizować liczbę klocków.
        licznik = 0;
    }

    return liczba_pol;
}

void opcje(int *liczba_opcji, int plansza[WIERSZE][KOLUMNY], int tablica_opcji[2][WIERSZE*KOLUMNY]) {
    // Symuluje różne opcje położenia klocka i wybiera te maksymalizujące ocenę planszy.
    int ocena_maksymalna = - WIERSZE*KOLUMNY;
    // Ocena maksymalna na pewno będzie większa od - WIERSZE*KOLUMNY.
    int ocena_obecna;
    int wskaznik_opcji = 0;

    for (int j = 0; j < WIERSZE; j++) {
        for (int i = 0; i < KOLUMNY; i++) {
            int klocek = 0;

            while ((j < WIERSZE) && ((klocek+i) < KOLUMNY) && (klocek < POLA) && (plansza[j][klocek+i]==0)) {
                klocek++;
            }
            if (klocek == POLA) {
                wpisz_klocek_prawy(j, i, plansza);
                ocena_obecna = ocena_prawego(plansza) - ocena_lewego(plansza);
                
                if (ocena_obecna == ocena_maksymalna){
                    // Jeśli ocena jest równa maksymalnej, należy dopisać analizowany klocek jako opcję.
                    tablica_opcji[0][wskaznik_opcji] = j;
                    tablica_opcji[1][wskaznik_opcji] = i;
                    wskaznik_opcji++;
                }
                else if (ocena_obecna > ocena_maksymalna) {
                    ocena_maksymalna = ocena_obecna;
                    wskaznik_opcji = 0;
                    tablica_opcji[0][wskaznik_opcji] = j;
                    tablica_opcji[1][wskaznik_opcji] = i;
                    wskaznik_opcji++;
                }

                usun_klocek_prawy(j, i, plansza);
            }
        }
    }

    *liczba_opcji = wskaznik_opcji;
}

void wybor(int *kropka, int *liczba_opcji, int tablica_opcji[2][WIERSZE*KOLUMNY], int plansza[WIERSZE][KOLUMNY]) {
    /* Spośród wszystkich dobrych ocen wybiera taką, która spełnia
    warunek zadania - wybrana zostaje ta opcja, której numer spełnia zależność
    <wybrana opcja> = WYBOR % <liczba opcji>. */
    if (*liczba_opcji != 0) {
        int numer = WYBOR % *liczba_opcji;
        int wiersz = tablica_opcji[0][numer];
        int kolumna = tablica_opcji[1][numer];

        wpisz_klocek_prawy(wiersz, kolumna, plansza);
        wypisywanie(wiersz, kolumna);
    }
    else {
        printf(".\n");
        *kropka = 1;
    }
}

int main() {
    int plansza[WIERSZE][KOLUMNY] = {0};
    int liczba_opcji = - WIERSZE*KOLUMNY;
    // - WIERSZE*KOLUMNY na pewno będą mniejsze niż jakakolwiek ocena planszy.
    int tablica_opcji[2][WIERSZE*KOLUMNY];
    /* W górnym wierszu tablica_opcji trzymam współrzędną wiersza,
    a w dolnym współrzędną kolumny. Mogę wpisać maksymalnie WIERSZE*KOLUMNY
    elementów, gdyż zostawiam sobie zapas pamięciowy, gdyż liczba rozważanych opcji
    na pewno będzie mniejsza lub równa WIERSZE*KOLUMNY, a uwzględniając numerację od 0
    zapewniamy, że liczba opcji nie wyjdzie ten poza zakres. */
    int kropka = 0;

    while (kropka != 1) {
        wczytywanie(&kropka, plansza);
        
        if (kropka != 1) {
            opcje(&liczba_opcji, plansza, tablica_opcji);
            wybor(&kropka, &liczba_opcji, tablica_opcji, plansza);
        }
    }

    return 0;
}
