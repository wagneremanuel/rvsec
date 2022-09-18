package br.unb.cic.mop.jca.util;

import java.util.HashMap;
import java.util.List;
import br.unb.cic.mop.jca.util.DefineAlgorithms;

public class CipherTransformationUtil {

    public static String alg(String transformation) {
        if (transformation.contains("/")) {
            return transformation.split("/")[0];
        }
        return transformation;
    }

    public static String mode(String transformation) {
        if (transformation.contains("/")) {
            return transformation.split("/")[1];
        }
        return "";
    }

    public static String pad(String transformation) {
        String[] arr = transformation.split("/");
        if (arr.length == 3) {
            return arr[2];
        }
        return "";
    }

    public static boolean isValid(String transformation) {

        List<String> modes = DefineAlgorithms.getValidCypherModes();
        HashMap<String, List<String>> padding = DefineAlgorithms.getCommonPaddings();

        if(alg(transformation).equals("AES")) {
            if(modes.contains(mode(transformation))) {
                return padding.get(mode(transformation)).contains(pad(transformation).toUpperCase());
            }
        }
        else if(alg(transformation).equals("RSA")) {
            List<String> rsaECBPaddings = DefineAlgorithms.getRSAECBPaddings();


            return (mode(transformation).equals("") && pad(transformation).equalsIgnoreCase("")) ||
                    (mode(transformation).equals("ECB") && rsaECBPaddings.contains(pad(transformation).toUpperCase()));
        }
        return false;
    }
}
