#include <iostream>
#include <unordered_set>
#include <algorithm>
#include <vector>
using namespace std;

int comparator(int first, int second) {
    return (first < second);
}

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    int n;
    int m;
    cin >> n;
    cin >> m;

    int table[n][m];

    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            int z;
            cin >> z;

            if (j < n/2) {
                table[z-1][i] = 0;
            }
            else {
                table[z-1][i] = 1;
            }
        }
    }

    long long table1[40000];

    for (int i = 0; i < 40000; i++) {
        table1[i] = -1;
    }

    for (int i = 0; i < n; i++) {
        long long sum = 0;
        for (int j = 0; j < m; j++) {
            sum = 2*sum + table[i][j];
        }

        table1[i] = sum;
    }

    sort(std::begin(table1), std::end(table1));

    bool error = 0;

    for (int i = 1; i < 40000; i++) {
        if ((table1[i] != -1) && (table1[i] == table1[i-1]))
        {
            cout << "NIE";
            error = 1;
            break;
        }
    }

    if (error == 0) {
        cout << "TAK";
    }
}
