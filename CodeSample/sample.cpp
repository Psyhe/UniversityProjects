void refresh() {
    // We turn off the previous digit.
    dot_off();
    digit_off();
    display_position_off(current_position);

    current_position = (current_position + 1) % NUMBER_OF_POSITIONS;
    // We turn on the next digit.
    display_position_on(current_position);
    light_digit[positions[current_position]]();
    // We want to have seconds.miliseconds timer,
    // so we light only central dot.
    if (current_position == 1) {
        dot_on();
    }
}
