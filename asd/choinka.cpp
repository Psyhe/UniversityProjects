#include <iostream>
#include <algorithm>
#include <vector>
#include <climits>
#include <math.h>
using namespace std;

const int my_max = 200007;
const int my_max_range = 530000;//524288;

const int strong = 1;
const int weak_strong = 2;
const int wrong = 3;
const int empty1 = 0;
int modifier;
int n;
int range_tree_size;

int *father = new int[my_max];
int *son = new int[my_max];
int *brother = new int[my_max];
long long *value = new long long[my_max];
    int *tree_to_preorder = new int[my_max];
    int *preorder_first_number = new int[my_max];
    int *preorder_second_number = new int[my_max];
    int *preorder_to_tree = new int[my_max];
    int *range_first = new int[my_max_range];
    int *range_last = new int[my_max_range];
    long long *main_value = new long long [my_max_range];
    long long *additional_value = new long long [my_max_range];
    int *status = new int[my_max_range];
    int *how_many = new int[my_max_range];

    int *how_many_main = new int[my_max_range];
   // int *how_many_additional = new int[my_max_range];

    int prev_status;
    long long prev_main;
    int prev_many_main;
    long long prev_additional;
    int prev_how_many;

    int temp_status;
    long long temp_main;
    int temp_many_main;
    long long temp_additional;
    int temp_how_many;


    int ile_drzewo_size() {
    int drzewo_size = 0;
    bool potega_2 = true;
    int licznik = 0;
    int n_kopia = n;
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

void writing(bool i) {
    if (!i) {
         cout << "NIE\n";
    }
    else {
         cout << "TAK\n";
    }
}

void set_default() {
    for (int i = 0; i < my_max; i++) {
        father[i] = empty1;
        son[i] = empty1;
        brother[i] = empty1;
        value[i] = empty1;
        tree_to_preorder[i] = empty1;
        preorder_first_number[i] = empty1;
        preorder_second_number[i] = empty1;
        preorder_to_tree[i] = empty1;
    }

    for (int i = 0; i < my_max_range; i++) {
        range_first[i] = empty1;
        range_last[i] = empty1;
        main_value[i] = empty1;
        additional_value[i] = empty1;
        status[i] = empty1;
        how_many[i] = empty1;
        how_many_main[i] = empty1;
    }
}

int cell_preorder(int vertex, int id) {
    preorder_first_number[vertex] = id;
    tree_to_preorder[vertex] = id;
    preorder_to_tree[id] = vertex;
    id++;
    int i = son[vertex];
    while (i != 0) {
        id = cell_preorder(i, id);
        i = brother[i];
    }

    preorder_second_number[vertex] = id - 1;
    return id;
}

void create_preorder() {

    int id = 1;
    cell_preorder(1, id);
}

void wczytywanie_bombek(int n) {
    for (int i = 1; i <= n; i++) {
        long long temp;
        cin >> temp;
        value[i] = temp;
    }
}

void copy_things(int status1, long long main_value1, int how_many_main1, long long additional1, int how_many1) {
    temp_status = status1;
    temp_main = main_value1;
    temp_many_main = how_many_main1;
    temp_additional = additional1;
    temp_how_many = how_many1;
}

void concatenate_things(int status1, long long main_value1, int how_many_main1, long long additional1, int how_many1,
                int status2, long long main_value2, int how_many_main2, long long additional2, int how_many2) {
    temp_status = strong;
    temp_main = main_value1;
    temp_many_main = how_many_main1 + how_many_main2;
    temp_how_many = how_many1 + how_many2;
}

void strong_and_weak(int statusS, long long main_valueS, int how_many_mainS, long long additionalS, int how_manyS,
                int statusW, long long main_valueW, int how_many_mainW, long long additionalW, int how_manyW) {
    if (main_valueS==main_valueW) {
        concatenate_things(statusS, main_valueS, how_many_mainS, additionalS, how_manyS, 
                            statusW, main_valueW, how_many_mainW, additionalW, how_manyW);
        temp_main = main_valueS;
        temp_status = weak_strong;
        temp_additional = additionalW;
    }
    else if (how_manyW == 2) {
        long long temp = additionalW;
        additionalW = main_valueW;
        main_valueW = temp;
        if (main_valueS==main_valueW) {
            concatenate_things(statusS, main_valueS, how_many_mainS, additionalS, how_manyS, 
                            statusW, main_valueW, how_many_mainW, additionalW, how_manyW);
            temp_main = main_valueS;
            temp_status = weak_strong;
            temp_additional = additionalW;
        }
        else {
            temp_status = wrong;
        }
    }
    else {
        temp_status = wrong;
    }
}

void know_things(int status1, long long main_value1, int how_many_main1, long long additional1, int how_many1,
                int status2, long long main_value2, int how_many_main2, long long additional2, int how_many2) {
    if (status1 == empty1) {
        copy_things(status2, main_value2, how_many_main2, additional2, how_many2);
        return;
    }
    else if (status2 == empty1) {
        copy_things(status1, main_value1, how_many_main1, additional1, how_many1);
        return;
    }

    if (status1 == wrong || status2 == wrong) {
        temp_status == wrong;
    }

    if (status1 == strong && status2 == strong) {
        if (main_value1 == main_value2) {
            concatenate_things(status1, main_value1, how_many_main1, additional1, how_many1,
                                status2, main_value2, how_many_main2, additional2, how_many2);
        }
        else if (how_many1 == 1) {
            concatenate_things(status1, main_value1, how_many_main1, additional1, how_many1,
                                status2, main_value2, how_many_main2, additional2, how_many2);
            temp_status = weak_strong;
            temp_main = main_value2;
            temp_many_main--;
            temp_additional = main_value1;
        }
        else if (how_many2 == 1) {
            concatenate_things(status1, main_value1, how_many_main1, additional1, how_many1,
                                status2, main_value2, how_many_main2, additional2, how_many2);
            temp_status = weak_strong;
            temp_main = main_value1;
            temp_many_main--;
            temp_additional = main_value2;
        }
        else {
            temp_status = wrong;
        }
    }
    else if (status1 == strong && status2 == weak_strong) {
        strong_and_weak(status1, main_value1, how_many_main1, additional1, how_many1,
                                status2, main_value2, how_many_main2, additional2, how_many2);
    }
    else if (status2 == strong && status1 == weak_strong) {
        strong_and_weak(status2, main_value2, how_many_main2, additional2, how_many2,
                                status1, main_value1, how_many_main1, additional1, how_many1);
    }
    else {
        temp_status = wrong;
    }
                
}

void clear_temp() {
    temp_status = empty1;
    temp_main = empty1;
    temp_many_main = empty1;
    temp_additional = empty1;
    temp_how_many = empty1;
}

void translate(int i, int j) {
    know_things(status[i], main_value[i], how_many_main[i], additional_value[i], how_many[i],
                status[j], main_value[j], how_many_main[j], additional_value[j], how_many[j]);
}

void update_status(int i) {
    clear_temp();
    translate(2*i, 2*i+1);
    status[i] = temp_status;
    main_value[i] = temp_main;
    how_many_main[i] = temp_many_main;
    additional_value[i] = temp_additional;
    how_many[i] = temp_how_many;
}

void update_prev(int i) {
    clear_temp();
    know_things(prev_status, prev_main, prev_many_main, prev_additional, prev_how_many,
                status[i], main_value[i], how_many_main[i], additional_value[i], how_many[i]);
    prev_status = temp_status;
    prev_main = temp_main;
    prev_many_main = temp_many_main;
    prev_additional = temp_additional;
    prev_how_many = temp_how_many;   
}

void basic_range_tree() {
    for (int i = 1; i <= n; i++) {
        int j = i + modifier;

        main_value[j] = value[preorder_to_tree[i]]; // wstepnie ok
        how_many[j] = 1;
        how_many_main[j] = 1;
        status[j] = strong;
    }

    for (int i = 1; i<=range_tree_size/2; i++) {
        int j = i + modifier;
        range_first[j] = i;
        range_last[j] = i;
    }

    // Updatowanie w gore
    int jj = modifier;
    while (jj > 0) {
        range_first[jj] = min(range_first[2*jj], range_first[2*jj+1]);
        range_last[jj] = max(range_last[2*jj], range_last[2*jj+1]);
        update_status(jj);
        jj--;
    }
}

void change(int tree_vertex, long long ball) {
    value[tree_vertex]  = ball;
    int preorder_vertex = tree_to_preorder[tree_vertex];
    main_value[preorder_vertex + modifier] = ball;
    
    int i = (preorder_vertex + modifier)/2;
    while (i>0) {
        update_status(i);
        i = i/2;
    }
}

void get_with_two_pointers(int i, int left_check, int right_check) {
    prev_status = empty1;
    prev_main = empty1;
    prev_many_main = empty1;
    prev_additional = empty1;
    prev_how_many = empty1; 

    int i_right = 2 * i + 1;
    int i_left = 2 * i;

    while (i_left < range_tree_size/2) {
        if (range_first[2*i_left+1] >= left_check && range_last[2*i_left+1] <= right_check) {
            update_prev(2*i_left+1);
            i_left = 2*i_left;
        }
        else {
            i_left = 2*i_left + 1;
        }
    }

    if (i_left > range_tree_size/2  && (range_first[i_left] >= left_check && range_last[i_left] <= right_check)) {
        update_prev(i_left);
    }

    while (i_right < range_tree_size/2) {
        if (range_first[2*i_right] >= left_check && range_last[2*i_right] <= right_check) {
            update_prev(2*i_right);
            i_right = 2* i_right+1;
        }
        else {
            i_right = 2*i_right;
        }
    }

    if (i_right > range_tree_size/2  && (range_first[i_right] >= left_check && range_last[i_right] <= right_check)) {
        update_prev(i_right);
    }

    if (prev_status == wrong) {
        writing(false);
    }
    else {
        writing(true);
    }

}

void get(int tree_vertex) {
    int preorder_vertex = tree_to_preorder[tree_vertex];

    int left_check= preorder_vertex;
    int right_check = preorder_second_number[tree_vertex];

    int what_now = 0;
    int i = 1;
    while (i < range_tree_size/2) {
        //if ((range_first[i] == right_check) && (left_check == range_last[i])) {

        if ((range_first[i] == left_check) && (right_check == range_last[i])) {
            bool info;
            if (status[i] == strong || status[i] == weak_strong) {
                info = true;
            }
            else {
                info = false;
            }
            writing(info);
            return;
        }

        if ((left_check >= range_first[2*i]) && (right_check <=range_last[2*i])) {
            i = 2*i;
        }
        else if ((left_check >= range_first[2*i+1]) && (right_check <=range_last[2*i+1])) {
            i = 2*i + 1;
        }
        else {
            // rozdzielamy sie
            what_now = 1;
            break;
        }
    }

    if (what_now==0) {
        writing(true);
    }
    else if (what_now == 1) {
        get_with_two_pointers(i, left_check, right_check);
    }
}

void wypisz_drzewo(string s, int tree_size, int tablica[]) {
     cout << s << endl;
    int start = 1;
    int finish = 2;
    while (start < tree_size) {
        for (int i = start; i < finish; i++) {
             cout << tablica[i] <<" ";
        }
         cout << endl;
        int temp = finish;
        finish = 2*finish;
        start = temp;
    }
}

void wypisz_drzewo_ll(string s, int tree_size, long long tablica[]) {
     cout << s << endl;
    int start = 1;
    int finish = 2;
    while (start < tree_size) {
        for (int i = start; i < finish; i++) {
             cout << tablica[i] <<" ";
        }
         cout << endl;
        int temp = finish;
        finish = 2*finish;
        start = temp;
    }
}

int main() {
    set_default();

    int q;
    cin >> n >> q;

    for (int i = 1; i <= n - 1; i++) {
        int temp_father;
        cin >> temp_father;
        father[i + 1] = temp_father;
        brother[i + 1] = son[temp_father];
        son[temp_father] = i + 1;
    }

    create_preorder();


    wczytywanie_bombek(n);
    range_tree_size = ile_drzewo_size();
    modifier = range_tree_size/2 - 1;
    basic_range_tree();

    for (int i = 0; i < q; i++) {
        //info
        char info;

        cin >> info;
        if (info == '?') {
            int tree_vertex;
            cin>> tree_vertex;
            get(tree_vertex);

        }
        else {
            int tree_vertex;
            long long ball;
            cin >> tree_vertex;
            cin >> ball;
            change(tree_vertex, ball);
        }
   }

    delete [] father;
    delete [] brother;
    delete [] son;

    delete [] value;
    delete [] additional_value;
    delete [] main_value;

    delete [] range_first;
    delete [] range_last;
    delete [] status;
    delete [] how_many_main;
    delete [] how_many;
}
