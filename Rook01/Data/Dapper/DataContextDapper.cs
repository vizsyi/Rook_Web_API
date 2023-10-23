using Dapper;
using Microsoft.Data.SqlClient;
using System.Data;

namespace Rook01.Data.Dapper
{
    public class DataContextDapper
    {
        //private readonly IConfiguration _config;
        private readonly string _connStr;

        public DataContextDapper(IConfiguration config)
        {
            //_config = config;
            _connStr = config.GetConnectionString("DefaultConnection");
        }

        public IEnumerable<T> LoadData<T>(string sql)
        {
            IDbConnection connection = new SqlConnection(_connStr);
            return connection.Query<T>(sql);
        }

        public IEnumerable<T> LoadDataWithParameters<T>(string sql, List<SqlParameter> parameters)
        {
            IDbConnection connection = new SqlConnection(_connStr);
            return connection.Query<T>(sql, parameters);
        }

        public T LoadDataSingle<T>(string sql)
        {
            IDbConnection connection = new SqlConnection(_connStr);
            return connection.QuerySingle<T>(sql);
        }

        public bool ExecuteSql(string sql)
        {
            IDbConnection connection = new SqlConnection(_connStr);
            return connection.Execute(sql) > 0;
        }

        //public bool ExecuteWithParameters(string sql, List<SqlParameter> parameters)
        public bool ExecuteWithParameters(string sql, DynamicParameters parameters)
        {
            IDbConnection connection = new SqlConnection(_connStr);
            return connection.Execute(sql, parameters) > 0;
        }
    }
}
