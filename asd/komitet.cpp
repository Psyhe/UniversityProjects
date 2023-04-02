#include <iostream>
#include <unordered_set>
#include <algorithm>
#include <vector>
#include <climits>
#include <math.h>
using namespace std;

long long comparator(long long first, long long second) {
    return (first < second);
}

const long long atrapa_nieskonczonosc = LLONG_MAX;
const long long atrapa_pusta = 0;
const long long upper = 1000000007;
const long long atrapa_blad = -1;
const long long atrapa_gorna = INT_MAX;
const long long max_size = 500000;


void wypisz1 (long long size, long long (co)[]) {
    for (long long i = 0; i < size; i++) {
        cout << co[i] << ",";
    }

    cout << endl;
}

void wypisz (long long size, long long (co)[]) {
    for (long long i = 0; i < size; i++) {
        cout << co[i] << ",";
    }

    cout << endl;
}

long long wyznacz_koncowa(long long(co)[], long long size, long long k) {
    long long limit = co[size - 1];

    for (long long i = 0; i < size; i++) {
        if (co[i] + k >= limit) {
            return i;
        }
    }

    return size - 1;
}

long long wyznacz_poczatkowa(long long(co)[], long long size, long long k) {
    long long limit = co[0];

    for (long long i = 0; i < size; i++) {
        if (co[i] - k > limit) {
            return i - 1;
        }
    }

    return size - 1;
}

long long ile_drzewo_size(long long n) {
    long long drzewo_size = 0;
    bool potega_2 = true;
    long long licznik = 0;
    long long n_kopia = n;
    while (n_kopia != 0) {
        if ((potega_2== true) && (n_kopia%2 == 1) && (n_kopia != 1)) {
            potega_2 = false;
            licznik++;
        }
        n_kopia = n_kopia/2;
        licznik++;
    }

    drzewo_size = pow(2, licznik);
    return drzewo_size;
}

long long policz_pierwszy_w(long long n, long long tablica[], long long szukaj) {
    long long srodek;
    long long poczatek = 0;
    long long koniec = n - 1;
    while (poczatek < koniec)
    {
        srodek = (poczatek + koniec) / 2;
        if (tablica[srodek] >= szukaj)           
            koniec = srodek;                  
        else                                
            poczatek = srodek + 1;      
    }

    if (tablica[poczatek] >= szukaj) {
        return poczatek;
    }
    else {
        return atrapa_gorna;
    }
}

void wczytaj_dane (long long modyfikator, long long dane[], long long tablica[], long long n) {
    for (long long i = 0; i < n; i++) {
        long long limit = dane[i] + modyfikator;
        tablica[i] = policz_pierwszy_w(n, dane, limit);
    }
}


long long znajdz_najdalszego_kandydata(long long n, long long dane[], long long pierwszy_poza[], long long odnosnik, long long i, long long ostatnia) {
    if (i <= ostatnia) { // jesli poprzedni jest rowny temu, w ktorym obecnie jestesmy to wszystko bez sensu
        return atrapa_blad;
    }

    // szukamy najdalszego takiego, ze pierwszy poza >= odnosnik
    long long srodek;
    long long poczatek = 0;
    long long koniec = n - 1;
    while (poczatek < koniec)
    {
        srodek = (poczatek + koniec) / 2;
        if (pierwszy_poza[srodek] >= odnosnik)             
            koniec = srodek;                  
        else                                 
            poczatek = srodek + 1;           
    }

    if (pierwszy_poza[poczatek] >= odnosnik) {
        return poczatek;
    }
    else {
        return atrapa_blad;
    }
}

void wypelnij_pozycje(long long n, long long pozycja_najdalszego_kandydata[] , long long dane[], 
                      long long limit_dolny[], long long limit_gorny[], long long ostatnia_poczatkowa) {
    for (long long i = 0; i < n; i++) {
        pozycja_najdalszego_kandydata[i] = 
        znajdz_najdalszego_kandydata(n, dane, limit_gorny, limit_dolny[i], i, ostatnia_poczatkowa);
    }
}

long long wyznacz_kandydata(long long start, long long drzewo_wartosc[], long long drzewo_size) {
    if (drzewo_wartosc[start] != atrapa_nieskonczonosc) {
        return start;
    }

    while (start > 1) {
        if (start % 2 == 0) { // jesli jestesmy w lewym poddrzewie, mozemy zrobic rzeczy
            if (drzewo_wartosc[start + 1] != atrapa_nieskonczonosc) {
                return start + 1;
            }
        }

        start = start / 2;
    }

    return atrapa_blad;
}


long long ile_kandydata(long long lokalny_kandydat, long long start, long long (drzewo_wartosc)[], long long (drzewo_ile_zestaw)[],
                        long long drzewo_size) {
    long long ile = 0;
    if (drzewo_wartosc[start] == lokalny_kandydat) {
        ile = drzewo_ile_zestaw[start] % upper;
    }
    while (start != 1) {
        if ((start % 2 == 0) && (start < drzewo_size - 1)) {
            if (drzewo_wartosc[start + 1] == lokalny_kandydat) {
                ile = (ile + drzewo_ile_zestaw[start + 1]) % upper;
            }
        }

        start = start / 2;
    }

    return ile;
}


long long policz_sume(long long lokalny_kandydat, long long poz_min, long long poz_maks,
                      long long drzewo_wartosc[], long long drzewo_ile_zestaw[],
                      long long drzewo_size, long long drzewo_przedzial[]) {

    bool niepuste = false;
    long long ile = 0;
    long long start = drzewo_size/2;
    long long poz_min_zw = poz_min - start;
    long long poz_max_zw = poz_maks - start;

    if (drzewo_przedzial[poz_min] < poz_max_zw) {
        if (drzewo_wartosc[poz_min] == lokalny_kandydat) {
            ile = drzewo_ile_zestaw[poz_min];

            if (ile != 0) {
                niepuste = true;
                ile = ile % upper;
            }
        }
        while (poz_min != 1) {
            if (poz_min % 2 == 0) {
                if (poz_max_zw <= drzewo_przedzial[poz_min + 1]) {
                    poz_min++;
                    break;
                }
                else if (drzewo_wartosc[poz_min + 1] == lokalny_kandydat) {
                               //     cout << "jestem tu" <<endl;

                    ile = (ile + drzewo_ile_zestaw[poz_min + 1]);
                    if (ile != 0) {
                        niepuste = true;
                        ile = ile % upper;
                    }
                }
            }

            poz_min = poz_min / 2;
        }
    }

    while (poz_min < drzewo_size/2) {
        if (drzewo_przedzial[2 * poz_min] < poz_max_zw) {
            if (drzewo_wartosc[2 * poz_min] == lokalny_kandydat) {
                ile = (ile + drzewo_ile_zestaw[2 * poz_min]);
                if (ile != 0) {
                    niepuste = true;
                    ile = ile % upper;
                }
            }
            poz_min = 2 * poz_min + 1;
        }
        else {
            poz_min = 2 * poz_min;
        }
    }

    if (niepuste == false) {
        return -1;
    }
    else {
        return ile % upper;
    }
}


int main() {

    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);
    long long n;
    long long k;
    long long l;
    cin >> n;
    cin >> k; /// nieostro mniejsze musi byc
    cin >> l; /// nieostro większe musi być

    long long pracownicy[max_size];
    long long *limit_gorny = new long long[n];
    long long *limit_dolny = new long long[n];
    long long *limit_l = new long long[n];

    for (long long i = 0; i < max_size; i++) {
        pracownicy[i] = LLONG_MAX;
    }

    for (long long i = 0; i < n; i++) {
        long long x;
        cin >> x;
        pracownicy[i] = x;
    }

    sort(std::begin(pracownicy), std::end(pracownicy));
    long long modyfikator_plus = k + 1;
    long long modyfikator_minus = -k;
    long long modyfikator_l = -l + 1;

    wczytaj_dane(modyfikator_plus, pracownicy, limit_gorny, n);
    wczytaj_dane(modyfikator_minus, pracownicy, limit_dolny, n);
    wczytaj_dane(modyfikator_l, pracownicy, limit_l, n);

    long long drzewo_size = ile_drzewo_size(n);
    long long *drzewo_wartosc = new long long[drzewo_size];
    long long *drzewo_ile_zestaw = new long long[drzewo_size];
    long long start = drzewo_size/2;

    for (long long i = 0; i < drzewo_size; i++) {
        drzewo_wartosc[i] = atrapa_nieskonczonosc;
        drzewo_ile_zestaw[i] = atrapa_pusta;
    }

    long long ostatnia_poczatkowa = wyznacz_poczatkowa(pracownicy, n, k);
    long long pierwsza_koncowa = wyznacz_koncowa(pracownicy, n, k);

    long long *pozycja_najdalszego_kandydata = new long long[n];

    wypelnij_pozycje(n, pozycja_najdalszego_kandydata ,pracownicy, limit_dolny, limit_gorny, ostatnia_poczatkowa);

    for (long long j = 0; j <= ostatnia_poczatkowa; j++) {
        long long jj = start + j;
        while (jj != 0) {
            drzewo_wartosc[jj] = 1;
            // JAK WOLNO WYRZUC TODO
            drzewo_ile_zestaw[jj] = (drzewo_ile_zestaw[jj] + 1) % upper;
            jj = jj/2;
        }
    }

    long long *drzewo_przedzial = new long long[drzewo_size];

    for (int i = 0; i < drzewo_size/2; i++) {
        drzewo_przedzial[i + drzewo_size / 2] = i;
    }


    int jj = drzewo_size / 4;
    while (jj > 0) {
        for (int ktory = jj; ktory < jj * 2; ktory++) {
            drzewo_przedzial[ktory] = max(drzewo_przedzial[2*ktory], drzewo_przedzial[2*ktory+1]);
        }
        jj = jj/2;
    }

    for (long long i = ostatnia_poczatkowa + 1; i < n; i++) {
        // WAZNE: dopisujemy wszedzie gdzie pozycja najdalszego kandydata + start
        long long pozycja_kandydata = wyznacz_kandydata(pozycja_najdalszego_kandydata[i] + start, drzewo_wartosc, drzewo_size);

        if (pozycja_kandydata == atrapa_blad) {
            continue;
        }
        long long lokalny_kandydat = drzewo_wartosc[pozycja_kandydata];

        long long local_count = policz_sume(lokalny_kandydat, pozycja_kandydata, limit_l[i] + start,
                                            drzewo_wartosc, drzewo_ile_zestaw, drzewo_size, drzewo_przedzial);

        if (local_count == atrapa_blad) {
            continue;
        }


        lokalny_kandydat++; //musimy zwiekszyc o 1
        long long j = i + start;


        while (j > 0) {
            if (lokalny_kandydat < drzewo_wartosc[j]) {
                drzewo_wartosc[j] = lokalny_kandydat;
                drzewo_ile_zestaw[j] = local_count % upper;
            }
            else if (lokalny_kandydat == drzewo_wartosc[j]) {
                drzewo_ile_zestaw[j] = (local_count % upper + drzewo_ile_zestaw[j] % upper) % upper;
            }

            j = j / 2;
        }

    }

    long long min_wartosc = atrapa_nieskonczonosc;
    long long ile = 0;
    for (long long i = pierwsza_koncowa; i < n; i++) {
        if (drzewo_wartosc[i + start] < min_wartosc) {
            min_wartosc = drzewo_wartosc[i + start];
        }
    }

    for (long long i = pierwsza_koncowa; i < n; i++) {
        if (drzewo_wartosc[i + start] == min_wartosc) {
            ile = (drzewo_ile_zestaw[i + start] + ile) % upper;
        }
    }

    delete [] pozycja_najdalszego_kandydata;
    delete [] drzewo_wartosc;
    delete [] drzewo_ile_zestaw;
    delete [] limit_gorny;
    delete [] limit_dolny;
    delete [] limit_l;
    delete [] drzewo_przedzial;

    cout << min_wartosc << " ";
    cout << ile << "\n";

    return 0;
}
