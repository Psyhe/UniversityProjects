/*
TOP7
authors: Maria Wysogląd, Iga Janik

This project informs users about the ranking of
songs in List of Hits. Project creates records
and summaries of votes and informs about the results.
*/
#include <iostream>
#include <regex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <inttypes.h>
#include <string>
#include <sstream>
#include <algorithm>

using namespace std;
using line_t = int64_t;
using max_t = int64_t;
// Stores number of a song.
using hit_number_t = int64_t;
/* Stores number of points (or number of votes, since they have
some similar features). */
using points_t = int64_t;
// Stores songs that were removed from the List of Hits.
using hit_trash_t = unordered_set<hit_number_t>;
// Stores every song's score.
using song_chart_t = unordered_map<hit_number_t, points_t>;
// Stores numbers of top 7 songs.
using public_chart_t = int64_t;
// Stores numbers of song in a given vote.
using vote_t = unordered_set<hit_number_t>;
// Connects a hit with its points.
using pair_hit_and_points_t = pair<hit_number_t, points_t>;

const int64_t MAX_RANK = 7;
const int64_t EMPTY = 0;
// Indicates empty position.
const int64_t NO_POSITION = 8;

// Function writes information about an error.
void write_error (string &input_line, line_t &n) {
    cerr << "Error in line " << n << ": " << input_line << endl;
}

// Function checks if there is a given hit in the song chart.
bool check_key(song_chart_t &map, hit_number_t &key) {
    if (map.count(key) == 0) {
        return false;
    }

    return true;
}

// Function adds votes into the chart.
void add_votes(song_chart_t &record, vote_t &song_points) {
    for (auto iter: song_points) {
        if (!check_key(record, iter)) {
            /* If a given song is not in the list, we add
            it to the chart. */
            pair_hit_and_points_t new_element;
            new_element.first = iter;
            new_element.second = 1;
            record.insert(new_element);
        }
        else {
            // If a song is in a list, we add one vote.
            record[iter] = record[iter] + 1;
        }
    }
}

// Function checks if vote is correct and stores the data in song chart.
void vote(string &input_line, line_t &line, max_t &max, hit_trash_t &waste,
          song_chart_t &record) {
    vote_t song_points;
    max_t newnumber = 0;
    bool if_error = false;

    regex number("([0-9]+)");
    auto iter = sregex_iterator(input_line.begin(), input_line.end(), number);

    while (iter != sregex_iterator()) {
        newnumber = stoi(iter->str());
        iter++;
        // Vote is for a song removed from List of Hits.
        if ((!waste.empty()) && (waste.find(newnumber) != waste.end())) {
            write_error(input_line, line);
            if_error = true;
            break;
        }
        // Vote is for a song with too high number.
        else if (newnumber > max) {
            write_error(input_line, line);
            if_error = true;
            break;
        }
        // There are two votes for the same song.
        else if (!song_points.empty()) {
            if (song_points.count(newnumber) == 0) {
                song_points.insert(newnumber);
            }
            else {
                write_error(input_line, line);
                if_error = true;
                break;
            }
        }
        else {
            song_points.insert(newnumber);
        }
    }

    // If no error occured, we can add votes.
    if (!if_error) {
        add_votes(record, song_points);
    }
}

// We set current values into previous chart.
void new_last(public_chart_t (&last)[], public_chart_t (&current)[]) {
    for (int64_t i = 0; i < MAX_RANK; i++) {
        last[i] = current[i];
    }
}

/* Funcion compares current record of summary with the previous one
and writes out the results.*/
void compare(public_chart_t (&current_record)[],
             public_chart_t (&last_record)[]) {
    for (int64_t i = 0; i < MAX_RANK; i++) {
        int64_t position = NO_POSITION;

        for (int64_t j = 0; j < MAX_RANK; j++) {
            if (last_record[j] == current_record[i]) {
                position = i - j;
                last_record[j] = EMPTY;
            }
        }

        if (current_record[i] != EMPTY) {
            cout << current_record[i] << " ";

            if (position == NO_POSITION) {
                cout << "-";
            }
            else {
                cout << -position;
            }

            cout << "\n";
        }
    }
}

// Function compares summaries.
void compare_summaries(public_chart_t (&current_summary)[],
                       public_chart_t (&last_summary)[]) {
    compare(current_summary, last_summary);
    new_last(last_summary, current_summary);
}

/* Function compares records and removes songs that are no longer
in a given record. (They are stored in <waste> now, so we can
check if a song is still in List of Hits ) */
void compare_records(public_chart_t (&current_record)[],
                     public_chart_t (&last_record)[], hit_trash_t &waste) {
    compare(current_record, last_record);

    for (int64_t i = 0; i < MAX_RANK; i++) {
        if (last_record[i] != EMPTY) {
            waste.insert(last_record[i]);
        }
    }

    new_last(last_record, current_record);
}

// Function sorts pairs according to the count of their points and numbers.
bool sort_chart(pair_hit_and_points_t i, pair_hit_and_points_t j) {
    if (i.second != j.second) {
        return (i.second > j.second);
    }
    else {
        return (i.first < j.first);
    }
}


/* Function creates new current summary or record. It stores the
data in a vector, sorts and set new public table of songs with
maximum number of votes or points. */
void new_current(public_chart_t (&current)[], song_chart_t &data) {
    vector<pair_hit_and_points_t> sorted;
    for (auto iter: data) {
        pair_hit_and_points_t new_element;
        new_element.first = iter.first;
        new_element.second = iter.second;
        sorted.push_back(new_element);
    }

    sort(sorted.begin(), sorted.end(), sort_chart);

    for (size_t i = 0; (i < MAX_RANK) && (i < sorted.size()); i++) {
        current[i] = (hit_number_t)sorted[i].first;
    }
}

// Function coordinates instructions connected with TOP order.
void new_summary(public_chart_t (&last_summary)[], song_chart_t &summary) {
    public_chart_t current_summary[MAX_RANK] = {0, 0, 0, 0, 0, 0, 0};

    new_current(current_summary, summary);
    compare_summaries(current_summary, last_summary);
}

// Function coordinates instructions connected with NEW MAX order.
void new_record(public_chart_t (&last_record)[],
                song_chart_t &record, song_chart_t &summary,
                hit_trash_t &waste) {
    public_chart_t current_record[MAX_RANK] = {0, 0, 0, 0, 0, 0, 0};
    new_current(current_record, record);

    for (int64_t i = 0; i < MAX_RANK; i++) {
        if (!(check_key(summary, current_record[i]))) {
            pair_hit_and_points_t new_element;
            new_element.first = current_record[i];
            new_element.second = MAX_RANK - i;

            /* Current table contains empty cells (with value of 0), which
            should not be added to the summary. */
            if (new_element.first != EMPTY) {
                summary.insert(new_element);
            }
        }
        else {
            summary[current_record[i]]
            = MAX_RANK - i + summary[current_record[i]];
        }
    }

    compare_records(current_record, last_record, waste);
    record.clear();
}

// Function sets new maximal value and checks if it meets the criteria. 
void newmax(max_t &max, string &input_line, line_t &line,
            public_chart_t (&last_record)[], song_chart_t &record,
            song_chart_t &summary, hit_trash_t &waste) {
    max_t new_max = 0;
    regex number("([0-9]+)");
    auto iter = sregex_iterator(input_line.begin(), input_line.end(), number);
    new_max = stoi((iter)->str());

    if (new_max >= max) {
        max = new_max;
        new_record(last_record, record, summary, waste);
    }
    else {
        write_error(input_line, line);
    }
}

// Function validates input and coordinates all instructions.
void read() {
    string input_line;
    line_t line_number = 0;
    max_t max = 0;
    public_chart_t last_record[MAX_RANK] = {0, 0, 0, 0, 0, 0, 0};
    public_chart_t last_summary[MAX_RANK] = {0, 0, 0, 0, 0, 0, 0};
    hit_trash_t waste;
    song_chart_t record;
    song_chart_t summary;

    regex new_max("[\\s]*NEW[\\s]*[0]*[1-9][0-9]{0,7}[\\s]*");
    regex new_vote("[\\s]*[0]*[1-9][0-9]{0,7}([\\s]+[0]*[1-9][0-9]{0,7})*[\\s]*");
    regex top("[\\s]*TOP[\\s]*");
    regex empty_line("[\\s]*");

    while (getline(cin, input_line)) {
        line_number++;

        if (regex_match(input_line, new_max)) {
            newmax(max, input_line, line_number, last_record,
            record, summary, waste);
        }
        else if (regex_match(input_line, new_vote)) {
            vote(input_line, line_number, max, waste, record);
        }
        else if (regex_match(input_line, top)) {
            new_summary(last_summary, summary);
        }
        else if (regex_match(input_line, empty_line)) {
        }
        else {
            write_error(input_line, line_number);
        }
    }
}

int main() {
    read();

    return 0;
}
