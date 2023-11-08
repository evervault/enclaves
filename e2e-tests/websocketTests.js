const { expect } = require('chai');
const assert = require('assert');
const WebSocket = require('ws');

describe('Make websocket request', () => {

    it("should start websocket session when authorised", (done) => {
      const options = {
        rejectUnauthorized: false,
        headers: {
          "api-key": "placeholder",
        },
      };

      const serverUrl = "wss://localhost:443/hello";

      const socket = new WebSocket(serverUrl, options);

      socket.on("open", () => {
        console.log("Connected to WebSocket server");
        socket.send("test connection");
      });

      socket.on("message", (data) => {
        console.log("Received message from server:", data.toString("utf8"));
        expect(data.toString("utf8")).to.equal(
          "SERVER RECIEVED MESSAGE: test connection"
        );
        console.log("message received");
        socket.close();
        done();
      });

      socket.on("error", (e) => {
        console.error("error in first test", e);
        done(e);
      });
    });

    it("should not start websocket session when not authorised", (done) => {
      const options = {
        rejectUnauthorized: false,
      };

      const serverUrl = "wss://localhost:443/hello";

      const socket = new WebSocket(serverUrl, options);

      socket.on("close", () => {
        console.log("websocket closed");
      });

      socket.on("open", () => {
        console.log("Connected to WebSocket server");
        try {
          socket.send("test connection");
        } catch (err) {
          console.error("Failed to send message to websocket server", err);
        }
      });

      socket.on("error", (err) => {
        expect(err.message).to.equal("Unexpected server response: 401");
        socket.close();
        done();
      });

      socket.on("message", () => {
        assert.fail("Connection was sucessful, 401 expected");
      });
    });

});