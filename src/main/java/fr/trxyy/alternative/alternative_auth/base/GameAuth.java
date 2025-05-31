package fr.trxyy.alternative.alternative_auth.base;

import com.sun.net.httpserver.HttpServer;
import fr.trxyy.alternative.alternative_api.GameEngine;
import fr.trxyy.alternative.alternative_auth.account.AccountType;
import fr.trxyy.alternative.alternative_auth.account.Session;
import fr.trxyy.alternative.alternative_auth.microsoft.MicrosoftAuth;
import fr.trxyy.alternative.alternative_auth.microsoft.ParamType;
import fr.trxyy.alternative.alternative_auth.microsoft.model.MicrosoftModel;
import fr.trxyy.alternative.alternative_auth.mojang.model.MojangAuthResult;
import javafx.application.Platform;
import javafx.collections.ListChangeListener;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.Pane;
import javafx.stage.Modality;
import javafx.stage.Stage;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import java.awt.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.text.DecimalFormat;
import java.util.UUID;

/**
 * GameAuth
 */
public class GameAuth {

    private static final int LOCAL_PORT = 51735;

    private final DecimalFormat ONE_DEC = new DecimalFormat(".#");

    private boolean isAuthenticated = false;
    private Session session = new Session();

    private AuthConfig authConfig;

    /*──────────────────────────  Constructeurs  ──────────────────────────*/

    public GameAuth(String user, String pwd, AccountType type) {
        AuthConstants.displayCopyrights();
        if (type == AccountType.MOJANG) {
            connectMinecraft(user, pwd);
        } else if (type == AccountType.OFFLINE) {
            setSession(user, TokenGenerator.generateToken(user), UUID.randomUUID().toString().replace("-", ""));
        }
    }

    public GameAuth(AccountType type) {
        AuthConstants.displayCopyrights();
    }

    /*──────────────────────  Auth Microsoft  ──────────────────────*/

    public void connectMicrosoft(GameEngine engine, Pane root) {
        this.authConfig = new AuthConfig(engine);

        ProgressIndicator spinner = new ProgressIndicator();
        spinner.setPrefSize(80, 80);
        StackPane content = new StackPane(spinner);
        content.setPadding(new Insets(20));

        Stage dlg = new Stage();
        dlg.setScene(new Scene(content, 300, 160));
        dlg.setTitle("Connexion Microsoft");
        dlg.initModality(Modality.APPLICATION_MODAL);
        dlg.setResizable(false);
        dlg.show();

        new Thread(() -> {
            try {
                if (authConfig.canRefresh()) {
                    Logger.log("Using stored Microsoft refresh_token …");
                    authConfig.loadConfiguration();
                    MicrosoftModel model = new MicrosoftAuth().getAuthorizationCode(
                            ParamType.REFRESH,
                            authConfig.microsoftModel.getRefresh_token());
                    authConfig.updateValues(model);
                    Session res = new MicrosoftAuth().getLiveToken(model.getAccess_token());
                    Platform.runLater(() -> success(res, dlg));
                    return;
                }

                LocalHttpReceiver receiver = new LocalHttpReceiver(LOCAL_PORT);
                MicrosoftAuth msAuth = new MicrosoftAuth();
                String state = UUID.randomUUID().toString();
                String authUrl = msAuth.getAuthorizationUrl(state);

                Desktop.getDesktop().browse(URI.create(authUrl));

                receiver.waitForCode().thenAccept(code -> {
                    try {
                        MicrosoftModel model = msAuth.getAuthorizationCode(ParamType.AUTH, code);
                        authConfig.createConfigFile(model);
                        Session res = msAuth.getLiveToken(model.getAccess_token());
                        Platform.runLater(() -> success(res, dlg));
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        Platform.runLater(() -> error(dlg));
                    } finally {
                        receiver.stop();
                    }
                });

            } catch (Exception e) {
                e.printStackTrace();
                Platform.runLater(() -> error(dlg));
            }
        }).start();
    }

    private void success(Session session, Stage dlg) {
        setSession(session.getUsername(), session.getToken(), session.getUuid());
        dlg.close();
    }

    private void error(Stage dlg) {
        this.isAuthenticated = false;
        dlg.close();
    }

    /*─────────────────  Serveur HTTP local  ─────────────────*/

    private static final class LocalHttpReceiver {
        private final HttpServer server;
        private final java.util.concurrent.CompletableFuture<String> codeFuture = new java.util.concurrent.CompletableFuture<>();

        LocalHttpReceiver(int port) throws IOException {
            server = HttpServer.create(new InetSocketAddress("localhost", port), 0);
            server.createContext("/callback", exchange -> {
                String query = exchange.getRequestURI().getRawQuery();
                String response = "<html><body>Connexion terminée, vous pouvez retourner dans le launcher.</body></html>";
                exchange.sendResponseHeaders(200, response.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
                if (query != null) {
                    for (String kv : query.split("&")) {
                        if (kv.startsWith("code=")) {
                            codeFuture.complete(kv.substring("code=".length()));
                            break;
                        }
                    }
                }
            });
            server.start();
        }

        java.util.concurrent.CompletableFuture<String> waitForCode() {
            return codeFuture;
        }

        void stop() {
            server.stop(0);
        }
    }

    /*──────────────────  Auth Mojang (inchangée)  ──────────────────*/

    public void connectMinecraft(String username, String password) {
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            HttpPost httpPost = new HttpPost(AuthConstants.MOJANG_BASE_URL);
            StringEntity parameters = new StringEntity(
                    "{\"agent\":{\"name\":\"Minecraft\",\"version\":1},\"username\":\"" + username + "\",\"password\":\"" + password + "\"}",
                    ContentType.create(AuthConstants.APP_JSON));
            httpPost.addHeader("content-type", AuthConstants.APP_JSON);
            httpPost.setEntity(parameters);
            try (CloseableHttpResponse resp = httpClient.execute(httpPost)) {
                BufferedReader br = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
                String json = br.readLine();
                if (!json.contains("\"name\"")) {
                    this.isAuthenticated = false;
                    return;
                }
                MojangAuthResult result = AuthConstants.getGson().fromJson(json, MojangAuthResult.class);
                setSession(result.getSelectedProfile().getName(), result.getAccessToken(), result.getSelectedProfile().getId());
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /*──────────────────  Setters / Getters  ──────────────────*/

    private void setSession(String user, String token, String id) {
        this.session.setUsername(user);
        this.session.setToken(token);
        this.session.setUuid(id);
        this.isAuthenticated = true;
        Logger.log("Connected successfully as " + user);
    }

    public void setSession(Session s) {
        setSession(s.getUsername(), s.getToken(), s.getUuid());
    }

    public boolean isLogged() {
        return isAuthenticated;
    }

    public Session getSession() {
        return session;
    }

    /* ------------------------------------------------------------------
     *  Tentative silencieuse : si un refresh_token est présent et valide
     *  → on met à jour la Session et on renvoie true.
     *  Sinon renvoie false et ne modifie rien.
     * ------------------------------------------------------------------ */
    public boolean trySilentRefresh(GameEngine engine) {
        try {
            this.authConfig = new AuthConfig(engine);   // même répertoire que d'habitude
            if (!authConfig.canRefresh()) return false; // aucun token stocké

            authConfig.loadConfiguration();             // lit alt_auth.json
            MicrosoftAuth ms = new MicrosoftAuth();

            MicrosoftModel m = ms.getAuthorizationCode(
                    ParamType.REFRESH,
                    authConfig.microsoftModel.getRefresh_token());

            // on persiste le nouveau couple access/refresh
            authConfig.updateValues(m);

            Session s = ms.getLiveToken(m.getAccess_token());
            setSession(s);                              // met à jour this.session + isAuthenticated
            return true;

        } catch (Exception ex) {
            Logger.log("Silent refresh failed : " + ex.getMessage());
            return false;                               // token absent, expiré ou invalide
        }
    }

}
