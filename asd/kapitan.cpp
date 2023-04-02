#include <iostream>
#include <cmath>
#include <algorithm>
#include <climits>
#include <vector>
#include <queue>

using namespace std;

const int maxw = 200001;

vector<pair<int, int>> graf_x;
vector<pair<int, int>> graf_y;

int x_wsp[maxw];
int y_wsp[maxw];

int old_number_x[maxw]; // chcemy z przenumerowanego dostac oryginalny
int old_number_y[maxw];

int new_number_x[maxw]; // chcemy z oryginalnego dostac nr nowego
int new_number_y[maxw];

int temp[maxw];

priority_queue<pair<int, int>> que;

int d[maxw];
int p[maxw];
bool checked[maxw];

int n;

void count_value(int T[], int T_wsp[], string s) {
    if (s== "W" || s== "E") {
        for (int i = 0; i < n; i++) {
            if (T[i] == INT_MAX) {
                T_wsp[i] = INT_MAX;
            }
            else {
                T_wsp[i] = abs(x_wsp[i] - x_wsp[T[i]]);
            }
        }
    }
    else {
        for (int i = 0; i < n; i++) {
            if (T[i] == INT_MAX) {
                T_wsp[i] = INT_MAX;
            }
            else {
                T_wsp[i] = abs(y_wsp[i] - y_wsp[T[i]]);
            }
        } 
    }

}

void cr_x(int T[], int T_wsp[], int modyfy, int start, int koniec, string s) {
    int prev = INT_MAX;
    for (int i = start; i != koniec; i+=modyfy) {
        T[old_number_x[i]] = prev;
        prev = old_number_x[i];
    }

    count_value(T, T_wsp, s);
}

void cr_y(int T[], int T_wsp[], int modyfy, int start, int koniec, string s) {
    int prev = INT_MAX;
    for (int i = start; i != koniec; i+=modyfy) {
        T[old_number_y[i]] = prev;
        prev = old_number_y[i];
    }
    count_value(T, T_wsp, s);
}

void create_graph(int N[], int S[], int W[], int E[], int N_wsp[], int S_wsp[], int W_wsp[], int E_wsp[]) {
    cr_x(W, W_wsp, 1, 0, n, "W");
    cr_x(E, E_wsp, -1, n-1, -1, "E");
    cr_y(S, S_wsp, 1, 0, n, "S");
    cr_y(N, N_wsp, -1, n-1, -1, "N");
}

void wypisz(int T[]) {
    for (int i = 0 ; i < n; i++) {
        cout << T[i] << " ";
    }
    cout << endl;
}

void set_basic() {
    for (int i = 0; i < maxw; i++) {
        p[i] = -1;
        d[i] = INT_MAX;
        checked[i] = false;
    }
}

// void add_cell(int i, int dl, int tab[], int tab_wsp[]) {
//     if (tab_wsp[i] != INT_MAX && !checked[tab[i]]) {
//         int element = dl + tab_wsp[i];
//         que.push(make_pair(element, tab[i]));
//     }
// }



void add_cell(int i, int dl, int T[], int T_wsp[]) {
    int dl_new = dl + T_wsp[i];
    if ((T[i] != INT_MAX) && (!checked[T[i]]) && (dl_new < d[T[i]])) {
        d[T[i]] = dl_new;
        que.push(make_pair(-dl_new, T[i]));
    }
}

void add_to_queue(int i, int dl, int N[], int S[], int W[], int E[], int N_wsp[], int S_wsp[], int W_wsp[], int E_wsp[]) {
    add_cell(i, dl, N, N_wsp);
    add_cell(i, dl, S, S_wsp);
    add_cell(i, dl, W, W_wsp);
    add_cell(i, dl, E, E_wsp);
}



void dijkstra(int N[], int S[], int W[], int E[], int N_wsp[], int S_wsp[], int W_wsp[], int E_wsp[]) {
    set_basic();
    d[0] = 0;
    add_to_queue(0, 0, N, S, W, E, N_wsp, S_wsp, W_wsp, E_wsp);
    checked[0] = true;
    int prev = 0;

    while(!que.empty()) {
        pair<int, int> temp_pair = que.top();
        que.pop();
      //  if (checked[temp_pair.second] == false) {}
        checked[temp_pair.second] = true;
        add_to_queue(temp_pair.second, -temp_pair.first, N, S, W, E, N_wsp, S_wsp, W_wsp, E_wsp);
    }

    cout << d[n-1] << endl;
}

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    cin >> n;
    int N[n];
    int S[n];
    int W[n];
    int E[n];

    int N_wsp[n];
    int S_wsp[n];
    int W_wsp[n];
    int E_wsp[n];

    for (int i = 0; i < n; i++) {
        int a, b;
        cin >> a >> b;
        graf_x.push_back(make_pair(a, i));
        graf_y.push_back(make_pair(b, i));
        x_wsp[i] = a;
        y_wsp[i] = b;

    }

    sort(graf_x.begin(), graf_x.end());
    sort(graf_y.begin(), graf_y.end());
    
    for (int i = 0; i <n; i++) {
        old_number_x[i] = graf_x[i].second;
        new_number_x[graf_x[i].second] = i;
        old_number_y[i] = graf_y[i].second;
        new_number_y[graf_y[i].second] = i;
    }

    //tworzenie wlasciwego grafu
    create_graph(N, S, W, E, N_wsp, S_wsp, W_wsp, E_wsp);

    dijkstra(N, S, W, E, N_wsp, S_wsp, W_wsp, E_wsp);
}
