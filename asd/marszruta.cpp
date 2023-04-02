/**
* @author Maria Wysogląd mw431552 (m.wysoglad@student.uw.edu.pl)
* @brief Rozwiązanie zadania
**/
#include <bits/stdc++.h>
#include <iostream>
#include <tuple>
#include <vector>
#include <math.h>
#include <algorithm>

using namespace std;

int n;
int m;
vector<vector<int>> sasiedzi;
vector<int> odwiedzone;
vector<int> w_trakcie;
vector<int> kolejnosc;
long long licznik = 0;

list<int> DFS(int start) {
    list<int> nowy;
    list<int> ostatni;
    int dodano = 0;
    w_trakcie[start] = 1;
    
    nowy.push_back(start);
    for (int i = 0; i < sasiedzi[start].size(); i++) {
        if (!w_trakcie[sasiedzi[start][i]]) {//} && !odwiedzone[sasiedzi[start][i]]) {
            list <int> tmp = DFS(sasiedzi[start][i]);
            if (tmp.back() == n-1) {
                swap(tmp, ostatni);
                dodano = 1;
            }
            else {
                nowy.splice(nowy.end(), tmp);
                nowy.push_back(start);
            }
        }
    }

    if (dodano == 1) {
        nowy.splice(nowy.end(), ostatni);
    }

    return nowy;
}

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    cin >> n;
    cin >> m;

    for (int i = 0; i < n; i++) {
        vector<int> nowy;
        sasiedzi.push_back(nowy);
        int x = 0;
        w_trakcie.push_back(x);
    }

    for (int i = 0; i < m; i++) {
        int x, y;
        cin >> x >> y;
        sasiedzi[x-1].push_back(y-1);
        sasiedzi[y-1].push_back(x-1);   
    }

    list<int> k = DFS(0);
    licznik = k.size();

    cout << licznik << '\n';
    for (int i = 0; i < licznik; i++) {
        cout << k.front() + 1 << " ";
        k.pop_front();
    }
}
