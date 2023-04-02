/**
* @author Maria Wysoglad mw431552 (m.wysoglad@student.uw.edu.pl)
* @brief Rozwiazanie zadania
**/
#include <bits/stdc++.h>
#include <iostream>
#include <tuple>
#include <vector>
#include <math.h>
#include <algorithm>

using namespace std;
long long n;
vector<long long> dane;
vector<long long> info_ciag;

const long long start = 1;
const long long nic = 0;
const long long koniec = 2;

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

        cin >> n;

    for (int long long i = 0; i < n; i++) {
        long long x;
        cin >> x;
        dane.push_back(x);
        info_ciag.push_back(nic);
    }
    long long zysk = 0;



    if (n == 1) {
        cout << zysk << "\n";
        exit(0);
    }
    else if (n == 2) {
        if (dane[0] < dane[1]) {
            zysk = dane[1] - dane[0];
            cout << zysk << "\n";
            exit(0);
        }
        else {
            cout << zysk << "\n";
            exit(0);
        }
    }

    info_ciag[0] = start;

    for (int i = 1; i < n; i++) {
        if (dane[i-1] > dane[i]) {
            info_ciag[i-1] = koniec;
            info_ciag[i] = start;
        }
    }

    if (dane[n-1] >= dane[n-2]) {
        info_ciag[n-1] = koniec;
    }

    bool czy_start = false;
    long long cena = -1;
    for (int i = 0; i < n; i++) {
        if (info_ciag[i] == start) {
            cena = dane[i];
            czy_start = true;
        }
        if (czy_start && info_ciag[i] == koniec && cena!= -1) {
            zysk += dane[i] - cena;
            cena = -1;
        }
    }

    cout << zysk << "\n";
}
