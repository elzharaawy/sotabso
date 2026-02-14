import mongoose from "mongoose";
import Grid from "gridfs-stream";

let gfs;

export const initGridFS = () => {
  const conn = mongoose.connection;
  Grid.mongo = mongoose.mongo;
  gfs = Grid(conn.db);
  gfs.collection("uploads");
};

export const getGridFS = () => gfs;
