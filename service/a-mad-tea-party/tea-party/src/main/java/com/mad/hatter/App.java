package com.mad.hatter;

import org.nustaq.serialization.FSTConfiguration;
import java.util.Scanner;
import java.util.InputMismatchException;
import com.mad.hatter.proto.CakeProto;
import org.apache.commons.codec.binary.Base64;


/**
 * Hello! I'm your friendly party organiser and cake designer!
 *
 */
public class App {

    static FSTConfiguration conf = FSTConfiguration.createDefaultConfiguration();

    public static void main(String[] args) {
        // Get the invitation code.
        String invitation_code = System.getenv("INVITATION_CODE").trim();

        // Initialise some common variables.
        Scanner scanner = new Scanner(System.in);

        // Create a cake with some simple defaults.
        CakeProto.Builder cakep = CakeProto.newBuilder()
            .setName("Placeholder Name")
            .setCandles(31337);

        // Print the Banner
        System.out.println("\n-- OH DON'T MIND THAT PISH POSH! --\n");
        System.out.println("Welcome to the March Hare's and Mad Hatter's Tea Party.");
        System.out.println("It's your Unbirthday! Hopefully...");
        System.out.println("Before we let you in, though... Why is a raven like a writing desk?");

        // Get the invitation code and check it.
        System.out.print("Invitation Code: ");
        String user_invite = scanner.next().trim();
        if (false && !user_invite.equals(invitation_code)) {
            System.out.println("That invitation code was wrong! Begone and good day!");
            return;
        }
        System.out.println("Correct! Welcome!");
        System.out.println("Come on into the party! But first, let's design you a cake!");

        // Run the main loop.
        boolean running = true;
        while (running) {
            System.out.println("[Cake Designer Interface v4.2.1]");
            System.out.println("  1. Set Name.");
            System.out.println("  2. Set Candles.");
            System.out.println("  3. Set Top Caption.");
            System.out.println("  4. Set Side Caption.");
            System.out.println("  5. Set Flavour.");
            System.out.println("\n  0. Leave the Party.");
            System.out.println("\nYour cake so far:\n");
            System.out.println(cakep);
            System.out.print("Choice: ");

            int choice = scanner.nextInt();
            switch (choice) {
                case 0:
                    running = false;
                    break;
                case 1:
                    String name = scanner.next().trim();
                    cakep.setName(name);
                    System.out.println("Name set!");
                    break;
                default:
                    System.out.println("That was not one of the options! Please listen!");
                    break;
            }
        }

        System.out.println("Hope you had fun! Bad day!");
    }
}
