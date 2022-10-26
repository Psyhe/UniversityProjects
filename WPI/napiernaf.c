/*
Napier-NAF
Program jest modułem implementującym interfejs <napiernaf.h>,
który zawiera funkcje:
<iton> (zmiana liczby int na reprezentację Napier-NAF),
<ntoi> (zmiana reprezentacji Napier-NAF na int, jeśli to możliwe),
<nadd> (dodawanie w reprezentacji),
<nsub> (odejmowanie w reprezentacji),
<nmul> (mnożenie w reprezentacji),
<nexp> (potęgowanie w reprezentacji),
<ndivmod> (wyznaczanie ilorazu i nieujemnej reszty z dzielenia w reprezentacji).

autor: Maria Wysogląd
*/
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
// Jeśli muszę zmienić jakąś tablicę, operuję na jej kopii, by nie niszczyć zawartości.

#define REPREZENTACJA_INT0 -1
#define REPREZENTACJA_INT1 31
/* Ze względu na późniejsze problemy z wychodzeniem poza zakres,
reprezentację INT_MAX definiuję osobno.
INT_MAX jest równy 2^31 - 1, wobec tego jego reprezentacją w Napier-NAF
będzie -1+31. */

/* Funkcja zwraca pozycję na której znajduje się liczba 1 lub -1 w reprezentacji BBR_NAF
względem cyfry w zapisie Napier-NAF.*/
int pozycja (int a) {
    if (a < 0) {
        a = abs(a) - 1;
    }

    return a;
}

// Funkcja kopiuje zawartość tablicy a do b.
void skopiuj (int *a, int an, int *b) {
    for (int i = 0; i < an; i++) {
        b[i] = a[i];
    }
}

/* Funkcja kopiuje zawartość a tablicy do b odwracając zapis - pierwsza liczba
jest ostatnią, a ostatnia pierwszą.*/
void skopiuj_odwrotnie (int *a, int an, int *b) {
    for (int i = 0; i < an; i++) {
        b[i] = a[an-1-i];
    }
}

// Funkcja oblicza cyfrę dzielnika w reprezentacji Napier-NAF.
int obliczanie_cyfry_ilorazu(int pierwsza_dzielna, int pierwszy_dzielnik) {
    int cyfra = 0;
    /* Aby obliczyć cyfrę ilorazu, trzeba obliczyć liczbę taką, że iloczyn
    obliczonej liczby (cyfry ilorazu) oraz pierwszej cyfry dzielnika będzie
    równy pierwszej cyfrze dzielnej w Napier-NAF.*/
        
    if ((pierwsza_dzielna < 0) && (pierwszy_dzielnik >= 0)) {
        // Aby otrzymać ujemną dzielną z nieujemnego dzielnika, trzeba dodać ujemną liczbę.
        cyfra = -(abs(pierwsza_dzielna) - pierwszy_dzielnik);
    }
    else if ((pierwsza_dzielna > 0) && (pierwszy_dzielnik < 0)) {
        // Aby otrzymać nieujemną dzielną z ujemnego dzielnika, trzeba dodać ujemną liczbę.
        cyfra = -(pierwsza_dzielna - abs(pierwszy_dzielnik) + 2);
    }
    else {
        // Jeśli cyfry są tego samego znaku, można po prostu odjąć ich wartości bezwzględne.
        cyfra = abs(pierwsza_dzielna) - abs(pierwszy_dzielnik);
    }

    return cyfra;
}

// Funkcja pomocnicza do <nonadjacent>, przeprowadza operacje na cyfrze z docelowej tablicy.
int aktualizacja_docelowej(int docelowa, int pierwotna, int rozmiar, int *czy_nadpisywac, int *nowa) {
    /* Cyfra pierwotna jest de facto potencjalną kolejną (bardziej znaczącą) cyfrą docelowej,
    ale o tym czy faktycznie jest i jakie modyfikacje musi przejść decydują warunki.*/
    if (docelowa + pierwotna == -1) {
        docelowa = 0;
        /* Jeśli liczba z tablicy pierwotnej i docelowej sumuje się do -1, oznacza to
        że 2 przeciwne cyfry po konwersji znajdowałyby się na tej samej pozycji w BBR-NAF,
        czyli się zerują, a miejsce to powinno pozostać puste.
        Wpisując 0 oznaczam tę pozycję jako miejsce, które powinno być puste
        i można je nadpisać, gdyż tylko 0-wa pozycja może być naturalnie równa 0.
        */
    }
    else if ((pierwotna >= 0) && (docelowa + 1 == pierwotna)) {
        /* Spełnienie tego warunku oznacza, że obok siebie występują dwie 1 (11) w BBR-NAF, 
        a to jest równoważne zapisowi (-101), gdzie ostatnia 1 jest na bardziej znaczącej 
        pozycji. Wobec tego docelowa musi zmienić swoją wartość w BBR-NAF na -1, 
        a nowa pozycja zostaje zapisana na zmiennej <nowa>*/
        docelowa = -pierwotna;
        *nowa = pierwotna + 1;
        *czy_nadpisywac = 1;
    }
    else if (((pierwotna >= 0) && (-docelowa == pierwotna)) || ((pierwotna < 0) && (pierwotna == docelowa))) {
        /* Spełnienie tego warunku oznacza, że obok siebie występuje (-11) w BBR-NAF, 
        a to jest równoważne zapisowi (10), gdzie ostatnie 0 jest na bardziej znaczącej 
        pozycji. Wobec tego docelowa musi zmienić swoją wartość w BBR-NAF na 1. */
        docelowa = pierwotna - 1;
    }
    else if ((pierwotna < 0) && (docelowa - 1 == pierwotna)) {
        /* Spełnienie tego warunku oznacza, że obok siebie występują dwie -1 (-1-1) w BBR-NAF, 
        a to jest równoważne zapisowi (10-1), gdzie ostatnia -1 jest na bardziej znaczącej 
        pozycji. Wobec tego docelowa musi zmienić swoją wartość w BBR-NAF na 1, 
        a nowa pozycja zostaje zapisana na zmiennej <nowa>*/
        docelowa = abs(pierwotna) - 2;
        *nowa = pierwotna - 1;
        *czy_nadpisywac = 1;
    }
    else if (((pierwotna < 0) && (-docelowa - 2 == pierwotna)) || ((pierwotna >= 0) && (pierwotna == docelowa))) {
        /* Spełnienie tego warunku oznacza, że obok siebie występują (1-1) w BBR-NAF, 
        a to jest równoważne zapisowi (-10), gdzie ostatnie 0 jest na bardziej znaczącej 
        pozycji. Wobec tego docelowa musi zmienić swoją wartość w BBR-NAF na -1. */
        docelowa = pierwotna + 1;
    }
    else {
        // Opisuje co dziele się poza przypadkami szczególnymi.
        if ((rozmiar == 0) || (docelowa != 0)) {
            *nowa = pierwotna;
            *czy_nadpisywac = 1;
        }
        else {
            /* Jeśli docelowa jest równa 0 i nie jest to pierwsza wpisywana cyfra,
            po prostu aktualizujemy docelową o kolejną cyfrę - 0 tu oznacza pustą
            pozycję wolną na zapis nowego elementu. */
            docelowa = pierwotna;
        }
    }

    return docelowa;
}

// Funkcja zmienia zapis liczby tak, by żadne cyfry różne od 0 w BBR_NAF nie stały obok siebie.
void nonadjacent(int *pierwotna, int n, int **c, int *cn) {
    // Funkcja zapisuje zmieniony zapis w tablicy docelowa;
    int *docelowa = NULL;
    int rozmiar = 1;

    if (n > 0) {
        // Jeśli pierwotna tablica jest pusta, nie trzeba niczego zmieniać.
        docelowa = realloc(docelowa, (size_t)n * sizeof(int));
        docelowa[rozmiar - 1] = pierwotna[0];
        rozmiar++;
    }

    for (int i = 1; i < n; i++) {
        int czy_nadpisywac = 0;
        int nowa;

        docelowa[rozmiar - 2] = aktualizacja_docelowej(docelowa[rozmiar - 2], pierwotna[i], rozmiar - 2, &czy_nadpisywac, &nowa);
        /* Jeśli nie nastąpiło w funkcji <aktualizacja_docelowej> nadpisanie na wolne
        miejsce oznaczone jako 0, wyprodukowana nowa liczba musi zostać wpisana
        do docelowej tablicy. */
        if (czy_nadpisywac == 1) {
            docelowa[rozmiar - 1] = nowa;
            rozmiar++;
        }
    }

    /* Może się zdarzyć, że w wyniku operacji z <aktualizacja_docelowej> na końcu reprezentacji
    pojawi się niepożądane 0, które nie może być brane pod uwagę w kolejnych operacjach.*/
    if ((n > 0) && ((docelowa[rozmiar - 2] == 0) && (rozmiar - 2 != 0))) {
        rozmiar--;
    }

    *c = docelowa;
    *cn = rozmiar - 1;
}

/* Funkcja aktualizuje zmienną pomocniczą <pom>, która była równa elementowi a, w związku
z tym wartość bezwzględna pom musi zostać zwiększona, w odpowiedni sposób dla a dodatniego
i ujemnego. */
int aktualizacja_pom(int a, int pom) {
    if (a >= 0) {
        pom = a + 1;
    }
    else {
        pom = a - 1;
    }

    return pom;
}

/* Funkcja pomocnicza dodawania umożliwiająca zmianę zmiennej <pom> będącej zmienną 
pomocniczą, służącą tymczasowemu przechowaniu wartości i późniejszemu umieszczeniu
na odpowiedniej pozycji.*/
void obsluga_pom (int *pomocnicza, int *rozmiar1, int a, int b, int *pom, int *i, int *j) {
    if(*pom != 0) {
        int ii = 0;
        int jj = 0;
        int rozmiar = *rozmiar1;

        if ((a != *pom) && (b != *pom)) {
            // Jeśli kolejna cyfra nie jest równa pom, pom może być wpisane do tablicy.
            pomocnicza[rozmiar - 1] = *pom;
            rozmiar++;
            *pom = 0;
        }
        else if (a == *pom) {
            // Jeśli kolejna cyfra jest równa pierwotnej, pom musi zostać zaktualizowane.
            *pom = aktualizacja_pom(a[i], *pom);
            ii++;
        }
        else if (b == *pom) {
            // Jeśli kolejna cyfra jest równa pierwotnej, pom musi zostać zaktualizowane.
            *pom = aktualizacja_pom(b[j], *pom);
            jj++;
        }

        *i += ii;
        *j += jj;
        *rozmiar1 = rozmiar;
    }
}

/* Kiedy dodajemy 2 liczby do siebie, w jednej z nich może zostać końcówka, która
nie zostaje uwzględniona we wspólnym dodawaniu i musi być dodana osobno.*/
int koniec_dodawania(int *pomocnicza, int *pierwotna, int bn, int rozmiar, int pom, int i, int j) {
    while (i < bn) {
        obsluga_pom(pomocnicza, &rozmiar, pierwotna[i], 0, &pom, &i, &j);
        pomocnicza[rozmiar - 1] = pierwotna[i];
        i++;
        rozmiar++;
    }

    return rozmiar;
}

// Funkcja dodaje do siebie reprezentacje dwóch liczb.
int czesc_wspolna_dodawanie(int *a, int *b, int *pomocnicza, int an, int bn, int rozmiar) {
    int i = 0;
    int j = 0;
    int pom = 0;
    /* <pom> jest zmienną pomocniczą, która przechowuje cyfrę powstającą w wyniku przepełnienia
    poprzedniej pozycji, jeśli ta pozycja jest wolna, <pom> może zostać użyte, w przeciwnym
    razie jest aktualizowane i może zostać użyte w kolejnych obrotach pętli. */

    while ((i < an) && (j < bn)) {
        obsluga_pom(pomocnicza, &rozmiar, a[i], b[j], &pom, &i, &j);

        if (a[i] == b[j]) {
            // Jeśli obie cyfry są takie same dochodzi do przepełnienia i <pom> musi być zaktualizowane.
            pom = aktualizacja_pom(a[i],pom);
        }
        else if(a[i]+b[j] != -1) {
            /* Jeśli suma cyfr jest równa -1, to następuje dodanie 2 liczb o tej samej pozycji
            i przeciwnych znakach i wyzerowanie, w przeciwnym wypadku, po uwzględnieniu przypadku
            cyfr równych (rozpatrzonego powyżej), następuje dopisanie kolejnej cyfry (o najmniejszej pozycji)
            w tablicy <pomocnicza>, będącej reprezentacją liczby będącej sumą a[i] i b[i]. */
            if (pozycja(a[i]) < pozycja(b[j])) {
                pomocnicza[rozmiar - 1] = a[i];
                j--;
            }
            else if (pozycja(b[j]) < pozycja(a[i])) {
                pomocnicza[rozmiar - 1] = b[j];
                i--;
            }
            rozmiar++;
        }

        i++;
        j++;
    }

    if ((pom != 0) && (i == an) && (j == bn)) {
        //Jeśli a i b skończyły się tą samą cyfrą, trzeba dopisać do tablicy wynikowej pozycję <pom>.
        pomocnicza[rozmiar - 1] = pom;
        rozmiar++;
    }

    /* Poniższe wyrażenia warunkowe umożliwiają dopisanie pozostałych cyfr liczby o większej
    wartości bezwzględnej, które nie zostały wpisane w powyższej pętli. */
    if(i < an) {
        rozmiar = koniec_dodawania(pomocnicza, a, an, rozmiar, pom, i, j);
    }

    if(j < bn) {
        rozmiar = koniec_dodawania(pomocnicza, b, bn, rozmiar, pom, j, i);
    }

    return rozmiar;
}


/* Funkcja pośrednicząca - sprawdza, czy chociaż jedna z liczb jest różna od 0 i alokuje 
pamięć na następne operacje. */
void dodawanie(int *a, int an, int *b, int bn, int **c, int *cn) {
    int *pomocnicza = NULL;
    int rozmiar = 0;

    pomocnicza = realloc(pomocnicza, (size_t)(an + bn) * sizeof(int));
    if ((an > 0) || (bn > 0)) {
        rozmiar++;
        rozmiar = czesc_wspolna_dodawanie(a, b, pomocnicza, an, bn, rozmiar);
    }

    *c = pomocnicza;
    *cn = rozmiar - 1;
}

void nadd(int *a, int an, int *b, int bn, int **c, int *cn) {
    int *adjacent, dlugosc;
    int *odp, odpn;

    dodawanie(a, an, b, bn, &adjacent, &dlugosc);
    nonadjacent(adjacent, dlugosc, &odp, &odpn);
    free(adjacent);
    /* W wyniku operacji <dodawanie> uzyskujemy reprezentację niejednocznaczną - w odpowiedniku
    BBR mogą występować obok siebie dwie cyfry różne od 0, <nonadjacent> zmienia reprezentację 
    w Napier-NAF, tak, by odpowiednik BBR był postaci BBR-NAF. */

    *c = odp;
    *cn = odpn;
}

// Funkcja oblicza rekurencyjnie potęgę liczby o podstawie a i wykładniku k.
long long potega(long long a, long long k) {
    if (k > 0) {
        long long odp;
        odp = potega(a, k - 1) * a;

        return odp;
    }
    else {
        return 1;
    }
}

/* Funkcja pomocnicza określająca ile pamięci potrzeba do iton tak, by zachować logarytmiczną
pamięć. */
int ile_zalokowac (long long x) {
    // Oblicza ile pamięci maksymalnie może zająć reprezentacja BBR-NAF.
    int ile = 0;
    while (x != 0) {
        if (x % 2 == 0) {
            x = x / 2;
        }
        else if ((x - 1) % 4 == 0) {
            x = (x - 1) / 2;
        }
        else {
            x = (x + 1) / 2;
        }

        ile++;
    }

    return ile;
}

void iton(int x, int **a, int *n) {
    int *pomocnicza = NULL;
    int rozmiar = 0;

    /* Przypadek INT_MAX musi być rozpatrzony osobno, gdyż jest liczbą nieparzystą
    i w wyniku operacji zawartych w <ile_zalokowac> nastąpiłoby wyjście poza zakres.*/
    if (x != INT_MAX) {   
        int wielkosc = ile_zalokowac(x);
        pomocnicza = realloc(pomocnicza, (size_t) wielkosc * sizeof(int));
        int pozycja =0;

        while (x != 0) {
            //Jeśli na danej pozycji ma wystąpić 1 lub -1, kod tej pozycji jest wpisywany do <pomocnicza>.
            if (x % 2 == 0) {
                x = x / 2;
            }
            else if ((x - 1) % 4 == 0) {
                pomocnicza[rozmiar]=pozycja;
                x = (x - 1) / 2;
                rozmiar++;
            }
            else {
                pomocnicza[rozmiar]=-pozycja-1;
                x = (x + 1) / 2;
                rozmiar++;
            }

            pozycja++;
        }
    }
    else {
        // Tworzy tablicę {-1, 31} reprezentującą INT_MAX.
        rozmiar = 2;
        pomocnicza = realloc(pomocnicza, (size_t)rozmiar * sizeof(int));
        pomocnicza[0] = REPREZENTACJA_INT0;
        pomocnicza[1] = REPREZENTACJA_INT1;
    }

    *a = pomocnicza;
    *n = rozmiar;
}

int ntoi(int *a, int n) {
    long long liczba = 0;
    // <liczba> może w pewnym momencie wyjść poza zakres int, stąd taki typ na początku.
    int koniec = 0;
    int i = n - 1;

    while (i >= 0 && koniec == 0) {
        long long czynnik;

        if (a[i] > REPREZENTACJA_INT1 || a[i] < -REPREZENTACJA_INT1-1) {
            /* Jeśli ostatnia cyfra jest większa od najbardziej znaczącej cyfry INT_MAX lub 
            mniejsza od najbardziej znaczącej cyfry INT_MIN to <liczba> na pewno jest poza
            zakresem int.*/
            koniec = 1;
            liczba = 0;
        }
        else {
            /*Jeśli liczba potencjalnie mieści się w int, dodawane są do niej potęgi 2
            odpowiadające pozycjom zakodowanym w reprezentacji.*/
            if (a[i] < 0) {
                czynnik = -potega(2, abs(a[i]) - 1);
            }
            else {
                czynnik = potega(2, a[i]);
            }

            liczba += czynnik;
            i--;
        }
    }

    if (liczba > INT_MAX || liczba < INT_MIN) {
        /* Nawet jeśli najbardziej znacząca cyfra mieści się w zakresie int, to pozostałe
        cyfry mogą spodowodać wyjście poza zakres int, który trzeba na koniec sprawdzić.*/
        liczba = 0;
    }

    return (int)liczba;
}

// Funkcja zamienia reprezentację Napier-NAF liczby na reprezentację liczby przeciwnej.
void negacja(int *b, int bn) {
    for (int i = 0; i < bn; i++) {
        b[i]= -b[i] - 1;
    }
}

void nsub(int *a, int an, int *b, int bn, int **c, int *cn) {
    int dn = bn;
    int *d = NULL;

    d = realloc(d, (size_t)dn * sizeof(int));
    skopiuj(b, bn, d);
    negacja(d, dn);
    nadd(a, an, d, dn, c, cn);
    // Odejmowanie jest równoważne dodawaniu liczby przeciwnej.

    free(d);
}

/* Funkcja umożliwiająca przeprowadzenie operacji <nonadjacent>, następnie wpisanie
wyniku na tablicę, która była wcześniej użyta; w szczególności na tablicę, której
używano w przeprowadzeniu operacji <nonadjacent>.*/
void posrednik_nonadjacent (int *a, int an, int **b, int *bn) {
    int *pomoc;
    int n;

    nonadjacent(a, an, &pomoc, &n);

    free(*b);
    *b = pomoc,
    *bn = n;
}

/* Funkcja umożliwiająca przeprowadzenie operacji <nadd>, następnie wpisanie
wyniku na tablicę, która była wcześniej użyta; w szczególności na tablicę, której
używano w przeprowadzeniu operacji <nadd>.*/
void posrednik_nadd (int *a, int an, int *b, int bn, int **c, int *cn) {
    int *pomoc;
    int n;

    nadd(a, an, b, bn, &pomoc, &n);

    free(*c);
    *c = pomoc,
    *cn = n;
}

/* Funkcja pomocnicza nmul i ndivmod. Gdy w Napier-NAF mnożymy dwie cyfry, 
tak naprawdę dodajemy ich reprezentacje w specyficzny sposób. Zauważmy, że
w tej reprezentacji wyrażenie a+b jest równoważne wyrażeniu 
2^(pozycja (a))*2^(pozycja(b)), z dokładnością do znaku (+/-).
Wobec tego jest to zakamuflowane mnożenie, ktore musi zostać przeprowadzone
z dokładnością do sposobu reprezentacji w Napier-NAF.*/
int obliczanie_cyfry (int a, int b) {
    int cyfra;

    if(((a >= 0) && (b >= 0))|| ((a < 0) && (b < 0))) {
        /* Gdy dwie cyfry są tego samego znaku, równnież ich reprezentacje
        w mnożeniu w standardowym systemie dziesiętnym są tego samego znaku,
        więc otrzymujemy w Napier-NAF cyfrę nieujemną, której dokładna wartość
        jest równa sumie pozycji a i b.*/
        cyfra = pozycja(a) + pozycja(b);
    }
    else {
        /* Gdy dwie cyfry są rożnego znaku, ich reprezentacje
        w mnożeniu w standardowym systemie dziesiętnym są ujemne,
        więc otrzymujemy w Napier-NAF cyfrę ujemną, której dokładna wartość
        jest równa sumie pozycji a i b, ze zmianą znaku na ujemny, oraz,
        ze względu na specyfikację Napier-NAF dla cyfr ujemnych, pomniejszoną 
        o 1, co jest równoważne poniższemu wyrażeniu.*/
        cyfra = -(abs(a) + abs(b));
    }

    return cyfra;
}

// Funkcja umożliwiająca odjęcie 1 i nadpisanie wyniku na użytej wcześniej tablicy.
void minusjeden (int*a, int an, int **c, int *cn) {
    int *minusjeden1 = NULL;
    int rozmiar_minusjeden = 1;

    minusjeden1 = realloc(minusjeden1, (size_t)rozmiar_minusjeden * sizeof(int));
    minusjeden1[0] = -1;
    // Reprezentacją -1 jest tablica {-1}.
    posrednik_nadd(a, an, minusjeden1, rozmiar_minusjeden, &a, &an);

    free(minusjeden1);
    *c = a;
    *cn = an;
}

void plusjeden (int*a, int an, int **c, int *cn) {
    int *plusjeden1 = NULL;
    int rozmiar_plusjeden = 1;

    plusjeden1 = realloc(plusjeden1, (size_t)rozmiar_plusjeden * sizeof(int));
    plusjeden1[0] = 0;
    // Reprezentacją 1 jest tablica {0}.
    posrednik_nadd(a, an, plusjeden1, rozmiar_plusjeden, &a, &an);

    free(plusjeden1);
    *c = a;
    *cn = an;
}

void nmul(int *a, int an, int *b, int bn, int **c, int *cn) {
    /* Mnożenie ma tutaj charakter podobny do mnożenia pisemnego - po przemnożeniu
    przez cyfrę, wynik pomocniczy dodawany jest do wyniku sumarycznego.*/
    int *sumaryczna = NULL;
    int rozmiar = 0;

    if ((an > 0) && (bn > 0)) {
        /* Jeśli rozmiar którejś reprezentacji jest równy 0, to reprezentuje ona liczbę 0,
        a mnożenie przez 0 zawsze w wyniku daje 0.*/
        for (int i = 0; i < bn; i++) {
            int *pomocnicza = NULL;
            int rozmiar_pom = 1;

            for (int j = 0; j < an; j++) {
                // Cyfra będąca wynikiem mnożenia dwóch cyfr jest generowana jak w <obliczanie_cyfry_mnozenie>.
                pomocnicza = realloc(pomocnicza, (size_t)rozmiar_pom * sizeof(int));           
                pomocnicza[rozmiar_pom - 1] = obliczanie_cyfry(a[j], b[i]);
                rozmiar_pom++;
            }

            rozmiar_pom--;
            posrednik_nadd(sumaryczna, rozmiar, pomocnicza, rozmiar_pom, &sumaryczna, &rozmiar);
            free(pomocnicza);
        }
    }

    *c = sumaryczna;
    *cn = rozmiar;
}

/* Funkcja umożliwiająca przeprowadzenie operacji <nmul>, następnie wpisanie
wyniku na tablicę, która była wcześniej użyta; w szczególności na tablicę, której
używano w przeprowadzeniu operacji <nmul>.*/
void posrednik_nmul (int *a, int an, int *b, int bn, int **c, int *cn) {
    int *pomoc;
    int n;

    nmul(a, an, b, bn, &pomoc, &n);
    free(*c);
    *c = pomoc,
    *cn = n;
}

void nexp(int *a, int an, int *b, int bn, int **c, int *cn) {
    int *liczba = NULL;
    int rozmiar = 1;
    int *wykladnik = NULL;
    int roz_wyk = bn;
    
    liczba = realloc(liczba, (size_t)rozmiar * sizeof(int));
    liczba[0] = 0;
    // Pierwotnie liczba jest równa {0}, co jest reprezentacją 1.

    if (roz_wyk != 0) {
        wykladnik = realloc(wykladnik, (size_t)roz_wyk * sizeof(int));
        skopiuj(b, roz_wyk, wykladnik);
    }

    while (roz_wyk != 0) {
        // Kiedy rozmiar wykładnika jest równy 0, to wykładnik również.
        posrednik_nmul(liczba, rozmiar, a, an, &liczba, &rozmiar);
        minusjeden(wykladnik, roz_wyk, &wykladnik, &roz_wyk);
    }

    *c = liczba;
    *cn = rozmiar;
}

/* Funkcja jest funkcją pomocniczą ndivmod, oblicza resztę i iloraz, przy czym obliczona reszta
może być ujemna. Funckja działa na zasadzie podobnej co dzielenie pisemne, z dokładnością
do mnożenia/dzielenia cyfr w reprezentacji Napier-NAF. Idea ogólna - dzielimy od
najbardziej znaczącej cyfry dzielnej przez najbardziej znaczącą cyfrę dzielnika i otrzymujemy
cyfrę ilorazu, następnie dodajemy przeciwną reprezentację iloczynu obliczonej cyfry ilorazu
oraz dzielnika. W ten sposób otrzymujemy nową dzielną z którą postępujemy analogicznie.*/
int pierwotne_divmod (int *a, int an, int *b, int bn, int **iloraz_faktyczny, int *rozmiar_iloraz_faktyczny, int **dzielna_faktyczna, int *rozmiar_dzielna_faktyczna) {
    int *iloraz = NULL;
    int rozmiar_iloraz = 0;
    int *dzielna = NULL;
    int rozmiar_dzielna = an;
    int pierwsza_dzielna = 0;

    if (rozmiar_dzielna != 0) {
        dzielna = realloc(dzielna, (size_t)rozmiar_dzielna * sizeof(int));
        skopiuj(a, an, dzielna);
        pierwsza_dzielna = dzielna[rozmiar_dzielna - 1];
        // Oznacza pierwszą cyfrę dzielnej.
    }

    int pierwszy_dzielnik = b[bn - 1];
    // Oznacza pierwszą cyfrę dzielnika.
    
    while (rozmiar_dzielna!=0 && (pozycja(pierwsza_dzielna) >= pozycja(pierwszy_dzielnik))) {
        /* Pętla obraca się dopóki dzielna nie będzie równa 0 lub dopóki prawdziwa 
        pozycja dzielnej nie będzie mniejsza od dzielnika, co oznacza, że dzielna nie
        jest już dzielną, ale resztą.*/
        iloraz = realloc(iloraz, (size_t)(rozmiar_iloraz + 1) * sizeof(int));
        iloraz[rozmiar_iloraz] = obliczanie_cyfry_ilorazu(pierwsza_dzielna, pierwszy_dzielnik);
        rozmiar_iloraz++;

        int *pomocnicza = NULL;
        /* Trzymamy w niej reprezentację liczby przeciwnej do iloczynu danej cyfry ilorazu
        oraz dzielnika.*/
        int rozmiar_pomocnicza = bn;
        pomocnicza = realloc(pomocnicza, (size_t) bn * sizeof(int));

        for (int i = bn - 1; i >= 0; i--) {
            pomocnicza[i] = - obliczanie_cyfry(iloraz[rozmiar_iloraz-1], b[i]) - 1;
            /* Obliczona cyfra, będąca iloczynem danej cyfry ilorazu oraz dzielnika musi zostać
            zmieniona na jej wartość przeciwną - tak jak w dzieleniu pisemnym od dzielnej
            odejmujemy iloczyn obliczonego dotychczas ilorazu i dzielnika, u mnie dzieje się 
            to równoważnie - poprzez zaktualizowanie dzielnej przez dodanie liczby przeciwnej
            do iloczynu dotychczasowego ilorazu oraz dzielnika.*/
        }
        posrednik_nadd(dzielna, rozmiar_dzielna, pomocnicza, rozmiar_pomocnicza, &dzielna, &rozmiar_dzielna);

        if (rozmiar_dzielna > 0) {
            pierwsza_dzielna = dzielna[rozmiar_dzielna - 1];
        }

        free(pomocnicza);
    }

    *iloraz_faktyczny = iloraz;
    *rozmiar_iloraz_faktyczny = rozmiar_iloraz;
    *dzielna_faktyczna = dzielna;
    *rozmiar_dzielna_faktyczna = rozmiar_dzielna;

    return rozmiar_iloraz;
}

void ndivmod(int *a, int an, int *b, int bn, int **q, int *qn, int **r, int *rn) {
    int *iloraz;
    int rozmiar_iloraz;
    int *dzielna;
    int rozmiar_dzielna;
    rozmiar_iloraz = pierwotne_divmod(a, an, b, bn, &iloraz, &rozmiar_iloraz, &dzielna, &rozmiar_dzielna);

    int *iloraz_faktyczny = NULL;
    int rozmiar_iloraz_faktyczny = rozmiar_iloraz;
    iloraz_faktyczny = realloc(iloraz_faktyczny, (size_t)rozmiar_iloraz_faktyczny * (sizeof(int)));

    skopiuj_odwrotnie(iloraz, rozmiar_iloraz, iloraz_faktyczny);
    posrednik_nonadjacent(iloraz_faktyczny, rozmiar_iloraz_faktyczny,&iloraz_faktyczny, &rozmiar_iloraz_faktyczny);
    /* Obliczony przez nas iloraz jest zapisany od najbardziej znaczącej cyfry z przodu, w związku
    z tym musi zostać zamieniony na Napier-NAF - z ostatnią najbardziej znaczącą cyfrą.*/

    if ((rozmiar_dzielna > 0) && (dzielna[rozmiar_dzielna - 1] < 0)) {
        /* Jeśli reszta z dzielenia obliczona w <pierwotne_divmod> jest ujemna,
        musi zostać zamieniona na liczbę dodatnią, a iloraz musi zostać, w zależności 
        od przypadku, zmniejszony lub zwiększony o 1. */
        if (b[bn - 1] >= 0) {
            minusjeden(iloraz_faktyczny, rozmiar_iloraz_faktyczny, &iloraz_faktyczny, &rozmiar_iloraz_faktyczny);
            posrednik_nadd(dzielna, rozmiar_dzielna, b, bn, &dzielna, &rozmiar_dzielna);
        }
        else {
            plusjeden(iloraz_faktyczny, rozmiar_iloraz_faktyczny, &iloraz_faktyczny, &rozmiar_iloraz_faktyczny);
            negacja(dzielna,rozmiar_dzielna);
            posrednik_nadd(dzielna, rozmiar_dzielna, b, bn, &dzielna, &rozmiar_dzielna);
            negacja(dzielna,rozmiar_dzielna);
        }
    }

    free(iloraz);
    *q = iloraz_faktyczny;
    *qn = rozmiar_iloraz_faktyczny;
    *r = dzielna;
    *rn = rozmiar_dzielna;
}