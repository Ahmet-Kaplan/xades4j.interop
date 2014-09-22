/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2014 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.interop.verification;

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import xades4j.verification.XAdESForm;

/**
 *
 * @author Luís
 */
public class SignatureVerificationTestCase {

    private static CertificateFactory certFactory;
    private static DocumentBuilder db;
    
    static
    {
        try {
            certFactory = CertificateFactory.getInstance("X.509");
                        
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            db = dbf.newDocumentBuilder();    
        }
        catch (CertificateException | ParserConfigurationException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    /**
     * Loads a set of test cases from the given directory. Each signature on the
     * directory results in a test case using the validation data (certificates
     * and CRLs) also in the directory.
     *
     * @param dir the directory to load test cases from
     * @return the test cases found on the given directory
     * @throws java.lang.Exception
     */
    public static Iterable<SignatureVerificationTestCase> loadFrom(File dir) throws Exception {
        File[] filesInTest = dir.listFiles(new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                return pathname.isFile();
            }
        });

        if (filesInTest.length == 0) {
            return Collections.emptyList();
        }

        List<SignatureVerificationTestCase> testCases = new ArrayList<>();
        
        Collection<Certificate> trustAnchors = new ArrayList<>();
        Collection<Certificate> certificates = new ArrayList<>();
        Collection<CRL> crls = new ArrayList<>();        
        
        for (File file : filesInTest) 
        {
            String[] fileNameParts = file.getName().split("\\.");
            if(fileNameParts.length < 2){
                throw new IllegalArgumentException("Missing file extension");
            }
            
            String ext = fileNameParts[fileNameParts.length - 1];
            FileInputStream stream = new FileInputStream(file);
            
            // Certificates
            if(ext.equals("cer") || ext.equals("crt"))
            {
                Certificate cert = certFactory.generateCertificate(stream);
                if(file.getName().startsWith("root"))
                {
                    trustAnchors.add(cert);
                }
                else
                {
                    certificates.add(cert);
                }
            }
            // CRLs
            else if(ext.equals("crl"))
            {
                crls.add(certFactory.generateCRL(stream));
            }
            // Signatures
            else if(ext.equals("xml") || ext.equals("xades"))
            {
                XAdESForm expectedForm = null;
                if(fileNameParts.length > 2)
                {
                    expectedForm = XAdESForm.valueOf(fileNameParts[fileNameParts.length - 2]);
                }
                
                testCases.add(new SignatureVerificationTestCase(
                        db.parse(stream),
                        expectedForm,
                        trustAnchors,
                        certificates,
                        crls,
                        dir.getName() + " - " + file.getName()));
            }
        }
        
        return testCases;
    }
    
    public final Document signatureDocument;
    public final XAdESForm expectedForm;
    public final Collection<Certificate> trustAnchors;
    public final Collection<Certificate> certificates;
    public final Collection<CRL> crls;
    private final String description;

    public SignatureVerificationTestCase(Document signatureDocument, XAdESForm expectedForm, Collection<Certificate> trustAnchors, Collection<Certificate> certificates, Collection<CRL> crls, String description) 
    {
        this.signatureDocument = signatureDocument;
        this.expectedForm = expectedForm;
        this.trustAnchors = trustAnchors;
        this.certificates = certificates;
        this.crls = crls;
        this.description = description;
    }

    @Override
    public String toString() {
        return description;
    }
}
