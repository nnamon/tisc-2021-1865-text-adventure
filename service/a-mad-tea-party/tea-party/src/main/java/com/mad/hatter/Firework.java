package com.mad.hatter;

import java.io.Serializable;

public class Firework implements Serializable {

    static final long serialVersionUID = 42L;

    public void fire() {
        System.out.println("This basic firework fizzles.");
    }

}
