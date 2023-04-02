#include <functional>
#include <queue>
#include <vector>
#include <iostream>
#include <string_view>
#include <list>
#include <iterator>
using namespace std;
int n;
int m;
int k;

// Liczba programistow, nr wierzcholka
priority_queue<pair<int, int>> analizowane;

int main() {
        std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);
    int ile_programistow[100001];

    list<int> co_zalezy[100001];

    int od_ilu_zalezy[100001];

    cin >> n;
    cin >> m;       
    cin >> k;

    for (int i = 0; i < 100001; i++) {
        ile_programistow[i] = 0;
        od_ilu_zalezy[i] = 0;
    }

    for (int i = 1; i <= n; i++) {
        int ile_p;
        cin >> ile_p;
        ile_programistow[i] = - ile_p;

    }

    for (int i = 1; i <= m; i++) {
        //  pierwsza zalezna od drugiej
        int a;
        int b;
        cin >> a >> b;  

        od_ilu_zalezy[a]++;
        co_zalezy[b].push_back(a);
    }

    for (int i = 1; i <= n; i++) {
        if (od_ilu_zalezy[i] == 0) {
            analizowane.push(make_pair(ile_programistow[i], i));
        }
    }

    int suma = 0;
    int ile_projektow = k;

    while (ile_projektow > 0) {
        pair<int, int> obecny = analizowane.top();
        analizowane.pop();

        if (abs(obecny.first) > suma) {
            suma = abs(obecny.first);
        }
        
        while (!co_zalezy[obecny.second].empty()) {
            int nastepny = co_zalezy[obecny.second].front();
            co_zalezy[obecny.second].erase(co_zalezy[obecny.second].begin());

            od_ilu_zalezy[nastepny]--;
            if (od_ilu_zalezy[nastepny] == 0) {
                analizowane.push(make_pair(ile_programistow[nastepny], nastepny));
            } 
        }
        ile_projektow--;
    }

    cout << suma;

    return 0;
}
